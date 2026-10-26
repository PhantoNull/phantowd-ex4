// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

func dosPrimaryFixture() []byte {
	h := make([]byte, 512)
	h[510], h[511] = 0x55, 0xaa
	setDOSPrimary(h, 0, 0x83, 16, 16)
	return h
}

func setDOSPrimary(h []byte, slot int, kind byte, first, count uint32) {
	e := h[446+slot*16 : 462+slot*16]
	clear(e)
	e[4] = kind
	binary.LittleEndian.PutUint32(e[8:], first)
	binary.LittleEndian.PutUint32(e[12:], count)
}

func TestDOSPrimaryRefusalsWithholdEveryPartition(t *testing.T) {
	cases := []struct {
		name   string
		change func([]byte)
		want   Status
	}{
		{"overlap", func(h []byte) { setDOSPrimary(h, 1, 0x83, 24, 8) }, StatusDamaged},
		{"zero-start", func(h []byte) { setDOSPrimary(h, 1, 0x83, 0, 8) }, StatusDamaged},
		{"zero-length", func(h []byte) { setDOSPrimary(h, 1, 0x83, 40, 0) }, StatusDamaged},
		{"outside-image", func(h []byte) { setDOSPrimary(h, 1, 0x83, 120, 16) }, StatusDamaged},
		{"noncanonical-unused", func(h []byte) { h[462] = 0x80 }, StatusDamaged},
		{"boot-flags", func(h []byte) { h[446] = 0x81 }, StatusDamaged},
		{"signature", func(h []byte) { h[511] = 0 }, StatusUnsupported},
	}
	for _, kind := range []byte{0x05, 0x0f, 0x85, 0xee, 0x51, 0x53, 0x54, 0x55} {
		cases = append(cases, struct {
			name   string
			change func([]byte)
			want   Status
		}{fmt.Sprintf("unsupported-%02x", kind), func(h []byte) { setDOSPrimary(h, 1, kind, 40, 8) }, StatusUnsupported})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := dosPrimaryFixture()
			tc.change(h)
			got, err := InspectDOSPrimary(bytes.NewReader(h), 128*512)
			if err != nil || got.Status != tc.want || got.PartitionCount != 0 || len(got.Partitions) != 0 || len(got.Findings) == 0 || got.WDCompatibility != "unqualified" {
				t.Fatalf("refusal exposed a partial table: %+v err=%v", got, err)
			}
		})
	}
}

type dosHeaderReader struct {
	header []byte
	calls  int
}

func (r *dosHeaderReader) ReadAt(p []byte, offset int64) (int, error) {
	r.calls++
	if offset != 0 || len(p) != 512 {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(p, r.header), nil
}

func TestDOSPrimaryBoundsWideExtentsAndEmptyTable(t *testing.T) {
	h := dosPrimaryFixture()
	const maximum = uint64(1<<32 - 1)
	setDOSPrimary(h, 0, 0x83, uint32(maximum-3), 4)
	reader := &dosHeaderReader{header: h}
	got, err := InspectDOSPrimary(reader, int64(maximum+1)*512)
	if err != nil || got.Status != StatusDOSPrimary || reader.calls != 1 || got.PartitionCount != 1 || got.Partitions[0].LastLBA != maximum || got.Partitions[0].SizeBytes != 2048 {
		t.Fatalf("wide extent or bounded read differs: %+v calls=%d err=%v", got, reader.calls, err)
	}
	setDOSPrimary(h, 0, 0x83, uint32(maximum-3), 5)
	got, err = InspectDOSPrimary(bytes.NewReader(h), int64(maximum+1)*512)
	if err != nil || got.Status != StatusDamaged || len(got.Partitions) != 0 {
		t.Fatal("32-bit wrap admitted", got, err)
	}
	for _, size := range []int64{0, 511, 513} {
		reader := &dosHeaderReader{header: h}
		got, err = InspectDOSPrimary(reader, size)
		if err != nil || got.Status != StatusDamaged || reader.calls != 0 || got.ImageMetadataRead {
			t.Fatal("invalid size read metadata", got, err)
		}
	}
	got, err = InspectDOSPrimary(&dosHeaderReader{header: h[:511]}, 128*512)
	if err == nil || got.ImageMetadataRead || len(got.Partitions) != 0 {
		t.Fatal("short read published observations", got, err)
	}
	if _, err = InspectDOSPrimary(nil, 512); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err = InspectDOSPrimary(bytes.NewReader(h), -1); err == nil {
		t.Fatal("negative size accepted")
	}
	clear(h[446:510])
	got, err = InspectDOSPrimary(bytes.NewReader(h), 128*512)
	if err != nil || got.Status != StatusDOSPrimary || got.PartitionCount != 0 || !got.RawIdentityRedacted || got.WDCompatibility != "unqualified" || got.MutationsPerformed || got.MountPerformed || got.AssemblyPerformed {
		t.Fatal("empty table is not a pristine/usable volume", got, err)
	}
	for i := 0; i < 4; i++ {
		setDOSPrimary(h, i, 0x83, uint32(16+10*i), 10)
	}
	got, err = InspectDOSPrimary(bytes.NewReader(h), 128*512)
	if err != nil || got.Status != StatusDOSPrimary || got.PartitionCount != 4 {
		t.Fatal("four adjacent primaries refused", got, err)
	}
	for i, p := range got.Partitions {
		if p.Number != i+1 {
			t.Fatal("slot numbers changed", got)
		}
	}
}

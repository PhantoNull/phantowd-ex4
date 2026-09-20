// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package uimage

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestInspectSyntheticKernel(t *testing.T) {
	fixture := syntheticImage([]byte("synthetic zImage"))
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || !report.MagicValid || !report.HeaderCRC32Valid || !report.DataCRC32Valid {
		t.Fatalf("unexpected invalid report: %+v", report)
	}
	if report.LoadAddress != "0x00008000" || report.EntryPoint != "0x00008000" {
		t.Fatalf("unexpected addresses: %+v", report)
	}
	if report.Architecture.Name != "arm" || report.ImageType.Name != "kernel" || report.Compression.Name != "none" {
		t.Fatalf("unexpected identities: %+v", report)
	}
}

func TestInspectDetectsCorruptPayload(t *testing.T) {
	fixture := syntheticImage([]byte("synthetic zImage"))
	fixture[len(fixture)-1] ^= 0xff
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.DataCRC32Valid {
		t.Fatalf("corrupt payload was accepted: %+v", report)
	}
}

func TestInspectDetectsCorruptHeader(t *testing.T) {
	fixture := syntheticImage([]byte("synthetic zImage"))
	fixture[32] ^= 0xff
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.HeaderCRC32Valid {
		t.Fatalf("corrupt header was accepted: %+v", report)
	}
}

func TestInspectRejectsTruncatedPayload(t *testing.T) {
	fixture := syntheticImage([]byte("synthetic zImage"))
	fixture = fixture[:len(fixture)-1]
	if _, err := Inspect(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
		t.Fatal("truncated payload was accepted")
	}
}

func TestInspectReportsUnauthenticatedTrailingBytes(t *testing.T) {
	fixture := append(syntheticImage([]byte("synthetic zImage")), 0)
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || report.TrailingBytes != 1 || len(report.Warnings) != 1 {
		t.Fatalf("trailing byte was not reported separately: %+v", report)
	}
}

func FuzzInspect(f *testing.F) {
	f.Add(syntheticImage([]byte("synthetic zImage")))
	f.Add([]byte("not a U-Boot image"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Inspect(bytes.NewReader(data), int64(len(data)))
	})
}

func syntheticImage(payload []byte) []byte {
	fixture := make([]byte, int(HeaderSize)+len(payload))
	header := fixture[:HeaderSize]
	binary.BigEndian.PutUint32(header[0:4], Magic)
	binary.BigEndian.PutUint32(header[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[16:20], 0x00008000)
	binary.BigEndian.PutUint32(header[20:24], 0x00008000)
	binary.BigEndian.PutUint32(header[24:28], crc32.ChecksumIEEE(payload))
	header[28] = 5
	header[29] = 2
	header[30] = 2
	header[31] = 0
	copy(header[32:64], "Synthetic Linux")
	copy(fixture[HeaderSize:], payload)
	binary.BigEndian.PutUint32(header[4:8], crc32.ChecksumIEEE(header))
	return fixture
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectMDV12SuperblockReportsRedactedCandidate(t *testing.T) {
	image := syntheticMDV12Image()
	if checksum := binary.LittleEndian.Uint32(mdV12Superblock(image, 16)[216:220]); checksum != 0xf2fe0b4e {
		t.Fatalf("independently calculated checksum fixture drifted: got %08x", checksum)
	}
	report, err := InspectMDV12Superblock(bytes.NewReader(image), int64(len(image)), 16, 95)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != MDStatusCandidate || report.MetadataVersion != "1.2" ||
		report.PartitionFirstLBA != 16 || report.PartitionLastLBA != 95 ||
		report.ArrayLevel != 1 || report.RAIDDisks != 2 || report.MemberNumber != 0 ||
		report.MemberRole != 0 || report.MaxDevices != 3 || report.Events != 42 ||
		report.ComponentDataOffsetSectors != 16 || report.ComponentDataSectors != 64 ||
		report.SuperblockChecksumStatus != "valid" || !report.RawIdentityRedacted ||
		!report.ImageMetadataRead || report.BlockDeviceOpened || report.MutationsPerformed ||
		report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected md report: %+v", report)
	}
	if report.ArrayIdentityFingerprint == "" || report.MemberIdentityFingerprint == "" {
		t.Fatal("nonzero md identities were not fingerprinted")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-array-uuid", "fixture-member-uuid", "PRIVATE_MD_SET_NAME", "/dev/sda"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaked %q: %s", secret, encoded)
		}
	}
}

func TestInspectMDV12SuperblockClassifiesMissingUnsupportedAndDamaged(t *testing.T) {
	image := syntheticMDV12Image()
	withoutMetadata := append([]byte(nil), image...)
	clear(withoutMetadata[16*logicalSectorBytes+mdV12SuperblockOffset : 16*logicalSectorBytes+mdV12SuperblockOffset+mdV1FixedBytes])
	report, err := InspectMDV12Superblock(bytes.NewReader(withoutMetadata), int64(len(withoutMetadata)), 16, 95)
	if err != nil || report.Status != MDStatusNotFound {
		t.Fatalf("missing magic: report=%+v err=%v", report, err)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
		status MDStatus
	}{
		{
			name:   "checksum mismatch",
			mutate: func(sb []byte) { sb[80] ^= 1 },
			status: MDStatusDamaged,
		},
		{
			name: "not v1.2 placement",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[144:152], 0)
				sealMDV1Superblock(sb)
			},
			status: MDStatusUnsupported,
		},
		{
			name:   "excessive role array",
			mutate: func(sb []byte) { binary.LittleEndian.PutUint32(sb[220:224], 4096) },
			status: MDStatusDamaged,
		},
		{
			name: "data region exceeds partition",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[136:144], 1<<40)
				sealMDV1Superblock(sb)
			},
			status: MDStatusDamaged,
		},
		{
			name: "data region overlaps metadata",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[128:136], 8)
				sealMDV1Superblock(sb)
			},
			status: MDStatusDamaged,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := syntheticMDV12Image()
			sb := mdV12Superblock(candidate, 16)
			test.mutate(sb)
			actual, err := InspectMDV12Superblock(bytes.NewReader(candidate), int64(len(candidate)), 16, 95)
			if err != nil || actual.Status != test.status {
				t.Fatalf("report=%+v err=%v", actual, err)
			}
		})
	}
}

func TestInspectMDV12SuperblockRejectsBadPartitionBounds(t *testing.T) {
	image := syntheticMDV12Image()
	for _, bounds := range [][2]uint64{{95, 16}, {16, 128}, {16, 23}} {
		report, err := InspectMDV12Superblock(bytes.NewReader(image), int64(len(image)), bounds[0], bounds[1])
		if err != nil || report.Status != MDStatusDamaged && report.Status != MDStatusUnsupported {
			t.Fatalf("bounds=%v report=%+v err=%v", bounds, report, err)
		}
	}
}

func FuzzInspectMDV12Superblock(f *testing.F) {
	f.Add(syntheticMDV12Image())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, image []byte) {
		if len(image) > 128*1024 {
			image = image[:128*1024]
		}
		if len(image) == 0 {
			return
		}
		sectors := uint64(len(image) / logicalSectorBytes)
		if sectors == 0 {
			return
		}
		_, _ = InspectMDV12Superblock(bytes.NewReader(image), int64(len(image)), 0, sectors-1)
	})
}

func syntheticMDV12Image() []byte {
	const sectors = 128
	image := make([]byte, logicalSectorBytes*sectors)
	sb := mdV12Superblock(image, 16)
	binary.LittleEndian.PutUint32(sb[0:4], mdV1Magic)
	binary.LittleEndian.PutUint32(sb[4:8], 1)
	copy(sb[16:32], []byte("fixture-array-uuid"))
	copy(sb[32:64], []byte("PRIVATE_MD_SET_NAME"))
	binary.LittleEndian.PutUint32(sb[72:76], 1)
	binary.LittleEndian.PutUint32(sb[92:96], 2)
	binary.LittleEndian.PutUint64(sb[128:136], 16)
	binary.LittleEndian.PutUint64(sb[136:144], 64)
	binary.LittleEndian.PutUint64(sb[144:152], mdV12SuperOffsetSectors)
	binary.LittleEndian.PutUint32(sb[160:164], 0)
	copy(sb[168:184], []byte("fixture-member-uuid"))
	binary.LittleEndian.PutUint64(sb[200:208], 42)
	binary.LittleEndian.PutUint32(sb[220:224], 3)
	binary.LittleEndian.PutUint16(sb[256:258], 0)
	binary.LittleEndian.PutUint16(sb[258:260], 1)
	binary.LittleEndian.PutUint16(sb[260:262], mdV1RoleSpare)
	sealMDV1Superblock(sb)
	return image
}

func mdV12Superblock(image []byte, firstLBA uint64) []byte {
	start := firstLBA*logicalSectorBytes + mdV12SuperblockOffset
	return image[start : start+mdV1FixedBytes+6]
}

func sealMDV1Superblock(sb []byte) {
	binary.LittleEndian.PutUint32(sb[216:220], 0)
	var sum uint64
	for i := 0; i+4 <= len(sb); i += 4 {
		sum += uint64(binary.LittleEndian.Uint32(sb[i : i+4]))
	}
	if len(sb)%4 == 2 {
		sum += uint64(binary.LittleEndian.Uint16(sb[len(sb)-2:]))
	}
	checksum := uint32(sum) + uint32(sum>>32)
	binary.LittleEndian.PutUint32(sb[216:220], checksum)
}

func TestInspectMDV090ComponentReportsRedactedCandidate(t *testing.T) {
	image := syntheticMDV090Component()
	if checksum := binary.LittleEndian.Uint32(mdV090Superblock(image)[mdV090ChecksumField : mdV090ChecksumField+4]); checksum != 0xd93c8ca5 {
		t.Fatalf("unexpected MD 0.90 checksum fixture: %08x", checksum)
	}
	report, err := InspectMDV090Component(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != MDV090StatusCandidate || report.MetadataVersion != "0.90" ||
		report.ComponentBytes != uint64(len(image)) || report.SuperblockOffsetBytes != uint64(len(image)-mdV090ReservedBytes) ||
		report.ArrayLevel != 1 || report.DeclaredDevices != 2 || report.RAIDDisks != 2 ||
		report.MemberNumber != 0 || report.MemberRole != 0 || report.MemberRoleDescription != "active-slot" ||
		report.Events != 42 || report.SuperblockChecksumStatus != "valid" || !report.RawIdentityRedacted ||
		!report.ImageMetadataRead || report.BlockDeviceOpened || report.MutationsPerformed ||
		report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected MD 0.90 report: %+v", report)
	}
	if report.ArrayIdentityFingerprint == "" {
		t.Fatal("nonzero MD 0.90 array UUID was not fingerprinted")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"MD090_PRIVATE_ARRAY_ID", "/dev/sda"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaked %q: %s", secret, encoded)
		}
	}
}

func TestInspectMDV090ComponentClassifiesMissingUnsupportedAndDamaged(t *testing.T) {
	image := syntheticMDV090Component()
	withoutMetadata := append([]byte(nil), image...)
	clear(mdV090Superblock(withoutMetadata))
	report, err := InspectMDV090Component(bytes.NewReader(withoutMetadata), int64(len(withoutMetadata)))
	if err != nil || report.Status != MDV090StatusNotFound {
		t.Fatalf("missing magic: report=%+v err=%v", report, err)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
		status MDV090Status
	}{
		{
			name:   "checksum mismatch",
			mutate: func(sb []byte) { sb[28] ^= 1 },
			status: MDV090StatusDamaged,
		},
		{
			name: "unsupported legacy version",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[8:12], 91)
				sealMDV090Superblock(sb)
			},
			status: MDV090StatusUnsupported,
		},
		{
			name: "inconsistent array counts",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[36:40], mdV090MaxDevices+1)
				sealMDV090Superblock(sb)
			},
			status: MDV090StatusDamaged,
		},
		{
			name: "member outside declared devices",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[mdV090ThisDiskOffset:mdV090ThisDiskOffset+4], 2)
				sealMDV090Superblock(sb)
			},
			status: MDV090StatusDamaged,
		},
		{
			name: "big-endian metadata",
			mutate: func(sb []byte) {
				binary.BigEndian.PutUint32(sb[0:4], mdV090Magic)
			},
			status: MDV090StatusUnsupported,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := syntheticMDV090Component()
			test.mutate(mdV090Superblock(candidate))
			actual, err := InspectMDV090Component(bytes.NewReader(candidate), int64(len(candidate)))
			if err != nil || actual.Status != test.status {
				t.Fatalf("report=%+v err=%v", actual, err)
			}
		})
	}
}

func TestInspectMDV090ComponentRejectsUnalignedAndSmallImages(t *testing.T) {
	unaligned := make([]byte, mdV090ReservedBytes+1)
	if report, err := InspectMDV090Component(bytes.NewReader(unaligned), int64(len(unaligned))); err != nil || report.Status != MDV090StatusDamaged {
		t.Fatalf("unaligned image: report=%+v err=%v", report, err)
	}
	small := make([]byte, mdV090ReservedBytes-logicalSectorBytes)
	if report, err := InspectMDV090Component(bytes.NewReader(small), int64(len(small))); err != nil || report.Status != MDV090StatusUnsupported {
		t.Fatalf("small image: report=%+v err=%v", report, err)
	}
}

func FuzzInspectMDV090Component(f *testing.F) {
	f.Add(syntheticMDV090Component())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, image []byte) {
		if len(image) > 128*1024 {
			image = image[:128*1024]
		}
		if len(image) == 0 {
			return
		}
		_, _ = InspectMDV090Component(bytes.NewReader(image), int64(len(image)))
	})
}

func syntheticMDV090Component() []byte {
	image := make([]byte, 1024*1024)
	sb := mdV090Superblock(image)
	binary.LittleEndian.PutUint32(sb[0:4], mdV090Magic)
	binary.LittleEndian.PutUint32(sb[4:8], 0)
	binary.LittleEndian.PutUint32(sb[8:12], 90)
	binary.LittleEndian.PutUint32(sb[12:16], 0)
	copy(sb[20:24], []byte("MD09"))
	binary.LittleEndian.PutUint32(sb[28:32], 1)
	binary.LittleEndian.PutUint32(sb[36:40], 2)
	binary.LittleEndian.PutUint32(sb[40:44], 2)
	copy(sb[52:56], []byte("PRIV"))
	copy(sb[56:60], []byte("ATE_"))
	copy(sb[60:64], []byte("ARRAY_ID"))
	binary.LittleEndian.PutUint32(sb[156:160], 42)
	binary.LittleEndian.PutUint32(sb[mdV090ThisDiskOffset:mdV090ThisDiskOffset+4], 0)
	binary.LittleEndian.PutUint32(sb[mdV090ThisDiskOffset+12:mdV090ThisDiskOffset+16], 0)
	sealMDV090Superblock(sb)
	return image
}

func mdV090Superblock(image []byte) []byte {
	if len(image) < mdV090ReservedBytes {
		return nil
	}
	offset := (len(image) &^ (mdV090ReservedBytes - 1)) - mdV090ReservedBytes
	return image[offset : offset+mdV090SuperblockBytes]
}

func sealMDV090Superblock(sb []byte) {
	binary.LittleEndian.PutUint32(sb[mdV090ChecksumField:mdV090ChecksumField+4], 0)
	var sum uint64
	for offset := 0; offset+4 <= len(sb); offset += 4 {
		sum += uint64(binary.LittleEndian.Uint32(sb[offset : offset+4]))
	}
	checksum := uint32(sum) + uint32(sum>>32)
	binary.LittleEndian.PutUint32(sb[mdV090ChecksumField:mdV090ChecksumField+4], checksum)
}

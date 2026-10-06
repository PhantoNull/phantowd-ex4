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

func TestInspectMDV10SuperblockUsesEndOfComponentPlacement(t *testing.T) {
	image := syntheticMDV10Image(0)
	report, err := InspectMDV10Superblock(bytes.NewReader(image), int64(len(image)), 16, 95)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != MDV10StatusCandidate || report.MetadataVersion != "1.0" ||
		report.PartitionFirstLBA != 16 || report.PartitionLastLBA != 95 ||
		report.SuperblockOffsetBytes != 16*logicalSectorBytes+64*logicalSectorBytes ||
		report.ArrayLevel != 1 || report.RAIDDisks != 2 || report.MaxDevices != 3 ||
		report.MemberNumber != 0 || report.MemberRole != 0 || report.MemberRoleDescription != "active-slot" ||
		report.Events != 42 || report.ComponentDataOffsetSectors != 0 || report.ComponentDataSectors != 64 ||
		report.SuperblockChecksumStatus != "valid" || report.ArrayIdentityFingerprint == "" ||
		!report.RawIdentityRedacted || !report.ImageMetadataRead || report.BlockDeviceOpened ||
		report.MutationsPerformed || report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected metadata 1.0 observation: %+v", report)
	}
	if binary.LittleEndian.Uint64(mdV10Superblock(image, 16, 95)[144:152]) != 64 {
		t.Fatal("synthetic fixture does not declare the expected component-relative superblock sector")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawIdentity := range []string{"fixture-array-uu"} {
		if strings.Contains(string(encoded), rawIdentity) {
			t.Fatalf("report leaked raw identity %q: %s", rawIdentity, encoded)
		}
	}
}

func TestInspectMDV10SuperblockWithholdsDamagedOrUnsupportedMetadata(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte)
		status MDV10Status
	}{
		{
			name: "checksum mismatch", status: MDV10StatusDamaged,
			mutate: func(sb []byte) { sb[80] ^= 1 },
		},
		{
			name: "declared metadata offset mismatch", status: MDV10StatusUnsupported,
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[144:152], 0)
				sealMDV1Superblock(sb)
			},
		},
		{
			name: "excessive role array", status: MDV10StatusDamaged,
			mutate: func(sb []byte) { binary.LittleEndian.PutUint32(sb[220:224], mdV1MaxDevices+1) },
		},
		{
			name: "component data overlaps metadata", status: MDV10StatusDamaged,
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[136:144], 65)
				sealMDV1Superblock(sb)
			},
		},
		{
			name: "zero array size", status: MDV10StatusDamaged,
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint64(sb[80:88], 0)
				sealMDV1Superblock(sb)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticMDV10Image(0)
			test.mutate(mdV10Superblock(image, 16, 95))
			report, err := InspectMDV10Superblock(bytes.NewReader(image), int64(len(image)), 16, 95)
			if err != nil || report.Status != test.status {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestInspectMDV10SuperblockRejectsBoundsAndUnalignedImages(t *testing.T) {
	image := syntheticMDV10Image(0)
	for _, bounds := range [][2]uint64{{95, 16}, {16, 128}, {16, 38}} {
		report, err := InspectMDV10Superblock(bytes.NewReader(image), int64(len(image)), bounds[0], bounds[1])
		if err != nil || report.Status != MDV10StatusDamaged && report.Status != MDV10StatusUnsupported {
			t.Fatalf("bounds=%v report=%+v err=%v", bounds, report, err)
		}
	}
	unaligned := append(image, 0)
	report, err := InspectMDV10Superblock(bytes.NewReader(unaligned), int64(len(unaligned)), 16, 95)
	if err != nil || report.Status != MDV10StatusDamaged {
		t.Fatalf("unaligned image: report=%+v err=%v", report, err)
	}
}

func FuzzInspectMDV10Superblock(f *testing.F) {
	f.Add(syntheticMDV10Image(0))
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
		_, _ = InspectMDV10Superblock(bytes.NewReader(image), int64(len(image)), 0, sectors-1)
	})
}

func syntheticMDV10Image(member uint32) []byte {
	const sectors = 128
	image := make([]byte, logicalSectorBytes*sectors)
	sb := mdV10Superblock(image, 16, 95)
	binary.LittleEndian.PutUint32(sb[0:4], mdV1Magic)
	binary.LittleEndian.PutUint32(sb[4:8], 1)
	copy(sb[16:32], []byte("fixture-array-uuid"))
	copy(sb[32:64], []byte("PRIVATE_MD_SET_NAME"))
	binary.LittleEndian.PutUint32(sb[72:76], 1)
	binary.LittleEndian.PutUint64(sb[80:88], 64)
	binary.LittleEndian.PutUint32(sb[92:96], 2)
	binary.LittleEndian.PutUint64(sb[136:144], 64)
	binary.LittleEndian.PutUint64(sb[144:152], 64)
	binary.LittleEndian.PutUint32(sb[160:164], member)
	copy(sb[168:184], []byte{byte(member + 1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	binary.LittleEndian.PutUint64(sb[200:208], 42)
	binary.LittleEndian.PutUint32(sb[220:224], 3)
	binary.LittleEndian.PutUint16(sb[256:258], uint16(member))
	binary.LittleEndian.PutUint16(sb[258:260], uint16(member))
	binary.LittleEndian.PutUint16(sb[260:262], mdV1RoleSpare)
	sealMDV1Superblock(sb)
	return image
}

func mdV10Superblock(image []byte, firstLBA, lastLBA uint64) []byte {
	sectors := lastLBA - firstLBA + 1
	superSector := (sectors - 16) &^ uint64(7)
	start := (firstLBA + superSector) * logicalSectorBytes
	return image[start : start+mdV1FixedBytes+6]
}

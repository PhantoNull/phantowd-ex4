// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mdmetadata

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestInspectPartitionRecognizesChecksummedMDV10WithoutExposingRawIDs(t *testing.T) {
	image := syntheticV10Image(0)
	result, err := InspectPartition(bytes.NewReader(image), int64(len(image)), Partition{Number: 1, StartLBA: 16, SizeLBA: 80})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCandidate || result.MetadataVersion != "1.0" ||
		result.SuperblockChecksumStatus != "valid" || result.RAIDDisks != 2 ||
		result.MemberNumber != 0 || result.MemberRole != 0 || result.MemberRoleDescription != "active-slot" ||
		result.ComponentDataSectors != 64 || result.Events != 42 ||
		result.ArrayIdentityFingerprint == "" || result.MemberIdentityFingerprint == "" {
		t.Fatalf("unexpected MD v1.0 observation: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil || bytes.Contains(encoded, []byte("fixture-md-array-id")) || bytes.Contains(encoded, []byte("fixture-md-member")) {
		t.Fatalf("raw MD identities escaped their private parser: %s %v", encoded, err)
	}
}

func TestInspectPartitionClassifiesChecksumDamageAndMissingMetadata(t *testing.T) {
	image := syntheticV10Image(0)
	partition := Partition{Number: 1, StartLBA: 16, SizeLBA: 80}
	const superblockOffset = (16 + 64) * 512
	corrupt := append([]byte(nil), image...)
	corrupt[superblockOffset+80] ^= 1
	result, err := InspectPartition(bytes.NewReader(corrupt), int64(len(corrupt)), partition)
	if err != nil || result.Status != StatusDamaged || result.SuperblockChecksumStatus != "invalid" {
		t.Fatalf("checksum corruption not withheld: %+v %v", result, err)
	}

	blank := make([]byte, len(image))
	result, err = InspectPartition(bytes.NewReader(blank), int64(len(blank)), partition)
	if err != nil || result.Status != StatusNotFound || !result.MetadataRead {
		t.Fatalf("missing metadata not classified: %+v %v", result, err)
	}
}

func TestInspectPartitionDoesNotTreatUnknownFeatureBitsAsCandidate(t *testing.T) {
	image := syntheticV10Image(0)
	const superblockOffset = (16 + 64) * 512
	binary.LittleEndian.PutUint32(image[superblockOffset+8:superblockOffset+12], 1)
	sealV1Superblock(image[superblockOffset : superblockOffset+262])
	result, err := InspectPartition(bytes.NewReader(image), int64(len(image)),
		Partition{Number: 1, StartLBA: 16, SizeLBA: 80})
	if err != nil || result.Status != StatusUnsupported || result.FeatureMap != 1 ||
		result.SuperblockChecksumStatus != "valid" {
		t.Fatalf("unknown feature bit was not withheld as unsupported: %+v %v", result, err)
	}
}

func TestInspectPartitionRejectsUnsafeRangesBeforeReading(t *testing.T) {
	image := syntheticV10Image(0)
	for _, partition := range []Partition{
		{},
		{Number: 1, StartLBA: 16, SizeLBA: 0},
		{Number: 1, StartLBA: 16, SizeLBA: 256},
		{Number: 1, StartLBA: ^uint64(0) - 1, SizeLBA: 4},
	} {
		if _, err := InspectPartition(bytes.NewReader(image), int64(len(image)), partition); err == nil {
			t.Fatalf("accepted invalid partition range: %+v", partition)
		}
	}
	if _, err := InspectPartition(nil, int64(len(image)), Partition{Number: 1, StartLBA: 16, SizeLBA: 80}); err == nil {
		t.Fatal("accepted a missing source")
	}
}

func FuzzInspectPartition(f *testing.F) {
	f.Add(syntheticV10Image(0), uint64(16), uint64(80))
	f.Add([]byte{}, uint64(0), uint64(0))
	f.Add(make([]byte, 4096), uint64(1), uint64(7))
	f.Fuzz(func(t *testing.T, image []byte, start, size uint64) {
		if len(image) > 1<<20 {
			image = image[:1<<20]
		}
		_, _ = InspectPartition(bytes.NewReader(image), int64(len(image)),
			Partition{Number: 1, StartLBA: start, SizeLBA: size})
	})
}

func syntheticV10Image(member uint32) []byte {
	const sectorBytes = 512
	const firstLBA = 16
	const partitionSectors = 80
	image := make([]byte, sectorBytes*128)
	superSector := (partitionSectors - 16) &^ uint64(7)
	start := (firstLBA + superSector) * sectorBytes
	sb := image[start : start+262]
	binary.LittleEndian.PutUint32(sb[0:4], 0xa92b4efc)
	binary.LittleEndian.PutUint32(sb[4:8], 1)
	copy(sb[16:32], []byte("fixture-md-array-id"))
	binary.LittleEndian.PutUint32(sb[72:76], 1)
	binary.LittleEndian.PutUint64(sb[80:88], 64)
	binary.LittleEndian.PutUint32(sb[92:96], 2)
	binary.LittleEndian.PutUint64(sb[136:144], 64)
	binary.LittleEndian.PutUint64(sb[144:152], superSector)
	binary.LittleEndian.PutUint32(sb[160:164], member)
	copy(sb[168:184], []byte{byte(member + 1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	binary.LittleEndian.PutUint64(sb[200:208], 42)
	binary.LittleEndian.PutUint32(sb[220:224], 3)
	binary.LittleEndian.PutUint16(sb[256:258], uint16(member))
	binary.LittleEndian.PutUint16(sb[258:260], uint16(member))
	binary.LittleEndian.PutUint16(sb[260:262], 0xffff)
	sealV1Superblock(sb)
	return image
}

func sealV1Superblock(superblock []byte) {
	binary.LittleEndian.PutUint32(superblock[216:220], 0)
	var sum uint64
	for index := 0; index < len(superblock); index += 4 {
		var word uint32
		if index+4 <= len(superblock) {
			word = binary.LittleEndian.Uint32(superblock[index : index+4])
		} else {
			var tail [4]byte
			copy(tail[:], superblock[index:])
			word = binary.LittleEndian.Uint32(tail[:])
		}
		sum += uint64(word)
	}
	binary.LittleEndian.PutUint32(superblock[216:220], uint32(sum)+uint32(sum>>32))
}

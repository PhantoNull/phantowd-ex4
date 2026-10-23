// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestInspectExtSuperblockReportsRecordedSpaceWithoutMigrationAuthority(t *testing.T) {
	image := syntheticGPTImage()
	putExtSuperblock(image, 40, extFixture{blockCount: 5, freeBlocks: 3, revision: 1,
		state: extStateClean, featureROCompat: extROCompatMetadataChecksum})
	sb := image[40*logicalSectorBytes+extSuperblockOffset : 40*logicalSectorBytes+extSuperblockOffset+extSuperblockBytes]
	binary.LittleEndian.PutUint32(sb[0x08:0x0c], 1)
	refreshExtSuperblockChecksum(sb)
	before := append([]byte(nil), image...)
	report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
	if err != nil || report.Status != ExtStatusCandidate {
		t.Fatalf("recorded space: report=%+v err=%v", report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Space *struct {
			FreeBlocks                 uint64 `json:"free_block_count"`
			ReservedBlocks             uint64 `json:"reserved_block_count"`
			FreeBytes                  uint64 `json:"free_bytes"`
			ReservedBytes              uint64 `json:"reserved_bytes"`
			UnreservedFreeBytes        uint64 `json:"unreserved_free_bytes"`
			MigrationCapacityQualified bool   `json:"migration_capacity_qualified"`
		} `json:"space_counters"`
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if result.Space == nil || result.Space.FreeBlocks != 3 || result.Space.ReservedBlocks != 1 ||
		result.Space.FreeBytes != 3072 || result.Space.ReservedBytes != 1024 ||
		result.Space.UnreservedFreeBytes != 2048 || result.Space.MigrationCapacityQualified {
		t.Fatalf("recorded space missing, incorrect or admitted for migration: %s", encoded)
	}
	if !bytes.Equal(before, image) {
		t.Fatal("space observation modified the source image")
	}
}

func TestInspectExtSuperblockUses64BitReservedCounter(t *testing.T) {
	const sectors = uint64(10_000_000_000)
	metadata := make([]byte, extSuperblockBytes)
	putExtSuperblockFields(metadata, extFixture{blockCount: 5, blockCountHigh: 1,
		freeBlocks: 3, freeBlocksHigh: 1, revision: 1, featureIncompat: extIncompat64Bit})
	binary.LittleEndian.PutUint32(metadata[0x08:0x0c], 1)
	binary.LittleEndian.PutUint32(metadata[0x154:0x158], 1)
	reader := fixedMetadataReader{offset: extSuperblockOffset, data: metadata}
	report, err := InspectExtSuperblock(reader, int64(sectors*logicalSectorBytes), 0, sectors-1)
	if err != nil || report.Status != ExtStatusCandidate || report.SpaceCounters == nil {
		t.Fatalf("64-bit space observation: report=%+v err=%v", report, err)
	}
	space := report.SpaceCounters
	if space.ReservedBlockCount != uint64(1)<<32|1 || space.FreeBlockCount != uint64(1)<<32|3 ||
		space.ReservedBytes != (uint64(1)<<32|1)*1024 || space.UnreservedFreeBytes != 2048 ||
		space.MigrationCapacityQualified {
		t.Fatalf("64-bit space counters lost or admitted: %+v", space)
	}
}

func TestInspectExtSuperblockRejectsInconsistentReservedCounters(t *testing.T) {
	for _, test := range []struct {
		name      string
		low, high uint32
		incompat  uint32
	}{
		{name: "reservation exceeds filesystem", low: 6},
		{name: "high reservation without 64-bit feature", high: 1},
		{name: "64-bit reservation exceeds filesystem", high: 1, incompat: extIncompat64Bit},
		{name: "maximum reservation cannot overflow bytes", low: ^uint32(0), high: ^uint32(0), incompat: extIncompat64Bit},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticGPTImage()
			putExtSuperblock(image, 40, extFixture{blockCount: 5, freeBlocks: 3, revision: 1,
				featureIncompat: test.incompat, featureROCompat: extROCompatMetadataChecksum})
			sb := image[40*logicalSectorBytes+extSuperblockOffset : 40*logicalSectorBytes+extSuperblockOffset+extSuperblockBytes]
			binary.LittleEndian.PutUint32(sb[0x08:0x0c], test.low)
			binary.LittleEndian.PutUint32(sb[0x154:0x158], test.high)
			refreshExtSuperblockChecksum(sb)
			report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
			if err != nil || report.Status != ExtStatusDamaged || report.SpaceCounters != nil {
				t.Fatalf("inconsistent reservation became usable counters: report=%+v err=%v", report, err)
			}
		})
	}
}

func TestInspectExtSpaceJSONDistinguishesZeroFromUnobserved(t *testing.T) {
	for _, test := range []struct {
		name           string
		free, reserved uint32
		mutate         func([]byte)
		observed       bool
	}{
		{name: "full filesystem", observed: true},
		{name: "reservation exceeds free space", free: 1, reserved: 3, observed: true},
		{name: "journal recovery is not migration admission", observed: true, mutate: func(sb []byte) {
			binary.LittleEndian.PutUint32(sb[0x60:0x64], extIncompatRecover)
			refreshExtSuperblockChecksum(sb)
		}},
		{name: "bad checksum", mutate: func(sb []byte) { sb[0x200] ^= 1 }},
		{name: "unsupported revision", mutate: func(sb []byte) { binary.LittleEndian.PutUint32(sb[0x4c:0x50], 2) }},
		{name: "not ext", mutate: func(sb []byte) { sb[0x38] = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticGPTImage()
			putExtSuperblock(image, 40, extFixture{blockCount: 5, freeBlocks: test.free, revision: 1,
				featureROCompat: extROCompatMetadataChecksum})
			sb := image[40*logicalSectorBytes+extSuperblockOffset : 40*logicalSectorBytes+extSuperblockOffset+extSuperblockBytes]
			binary.LittleEndian.PutUint32(sb[0x08:0x0c], test.reserved)
			refreshExtSuperblockChecksum(sb)
			if test.mutate != nil {
				test.mutate(sb)
			}
			report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
			if err != nil || report.SchemaVersion != 3 {
				t.Fatalf("report contract: %+v %v", report, err)
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &object); err != nil {
				t.Fatal(err)
			}
			value, exists := object["space_counters"]
			if !exists || (string(value) != "null") != test.observed {
				t.Fatalf("unknown/full distinction missing: %s", encoded)
			}
			if test.observed {
				space := report.SpaceCounters
				if space.FreeBytes != uint64(test.free)*1024 || space.UnreservedFreeBytes != 0 || space.MigrationCapacityQualified {
					t.Fatalf("zero space wrapped or gained authority: %+v", space)
				}
				for _, field := range []string{`"free_bytes":`, `"reserved_bytes":`, `"unreserved_free_bytes":0`, `"migration_capacity_qualified":false`} {
					if !bytes.Contains(value, []byte(field)) {
						t.Fatalf("zero or refusal omitted: %s", value)
					}
				}
			}
		})
	}
}

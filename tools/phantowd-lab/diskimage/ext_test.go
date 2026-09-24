// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInspectExtSuperblockReportsBoundedGenericMetadata(t *testing.T) {
	image := syntheticGPTImage()
	putExtSuperblock(image, 40, extFixture{
		blockCount:      5,
		freeBlocks:      2,
		blockSizeLog:    0,
		state:           1,
		revision:        1,
		featureIncompat: 0x44,
		featureROCompat: 0x400,
	})
	report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != ExtStatusCandidate || report.FilesystemFamily != "ext-family" ||
		report.PartitionFirstLBA != 40 || report.PartitionLastLBA != 49 || report.PartitionBytes != 10*logicalSectorBytes ||
		report.BlockSizeBytes != 1024 || report.BlockCount != 5 || report.FilesystemBytes != 5*1024 ||
		report.FreeBlockCount != 2 || report.FeatureIncompat != 0x44 || report.FeatureROCompat != 0x400 ||
		report.SuperblockChecksumStatus != "present-not-validated" || !report.CleanUnmount || !report.NeedsJournalRecovery || !report.RawIdentityRedacted ||
		!report.ImageMetadataRead || report.BlockDeviceOpened || report.MutationsPerformed || report.MountPerformed {
		t.Fatalf("unexpected ext superblock report: %+v", report)
	}
	if report.FilesystemIdentityFingerprint == "" {
		t.Fatal("nonzero dynamic-revision filesystem UUID was not fingerprinted")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-ext-uuid", "EXT4_PRIVATE_LABEL", "/dev/sda", "fixture-private-path"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaked %q: %s", secret, encoded)
		}
	}
}

func TestInspectExtSuperblockClassifiesAbsentAndUnsupportedMetadata(t *testing.T) {
	image := syntheticGPTImage()
	report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
	if err != nil || report.Status != ExtStatusNotFound || report.FilesystemFamily != "unknown" {
		t.Fatalf("no ext magic: report=%+v err=%v", report, err)
	}

	putExtSuperblock(image, 40, extFixture{blockCount: 5, blockSizeLog: 0, revision: 1})
	for _, test := range []struct {
		name   string
		mutate func([]byte)
		status ExtStatus
	}{
		{
			name: "block count exceeds containing partition",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[4:8], 6)
			},
			status: ExtStatusDamaged,
		},
		{
			name: "unsupported block size exponent",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[24:28], 7)
			},
			status: ExtStatusUnsupported,
		},
		{
			name: "unsupported revision",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[76:80], 2)
			},
			status: ExtStatusUnsupported,
		},
		{
			name: "free block count exceeds total",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[12:16], 6)
			},
			status: ExtStatusDamaged,
		},
		{
			name: "high block count without 64-bit feature",
			mutate: func(sb []byte) {
				binary.LittleEndian.PutUint32(sb[0x150:0x154], 1)
			},
			status: ExtStatusDamaged,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := append([]byte(nil), image...)
			sb := fixture[int(40*logicalSectorBytes+1024):int(40*logicalSectorBytes+2048)]
			test.mutate(sb)
			report, err := InspectExtSuperblock(bytes.NewReader(fixture), int64(len(fixture)), 40, 49)
			if err != nil || report.Status != test.status {
				t.Fatalf("ext superblock status=%q want %q: report=%+v err=%v", report.Status, test.status, report, err)
			}
		})
	}
}

func TestInspectExtSuperblockRejectsInvalidPartitionBounds(t *testing.T) {
	image := syntheticGPTImage()
	for _, test := range []struct {
		name      string
		diskSize  int64
		firstLBA  uint64
		lastLBA   uint64
		wantState ExtStatus
	}{
		{name: "partition shorter than superblock", diskSize: int64(len(image)), firstLBA: 40, lastLBA: 42, wantState: ExtStatusUnsupported},
		{name: "reversed LBA bounds", diskSize: int64(len(image)), firstLBA: 41, lastLBA: 40, wantState: ExtStatusDamaged},
		{name: "partition exceeds image", diskSize: int64(len(image)), firstLBA: 120, lastLBA: 128, wantState: ExtStatusDamaged},
		{name: "unaligned image", diskSize: int64(len(image) - 1), firstLBA: 40, lastLBA: 49, wantState: ExtStatusDamaged},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := InspectExtSuperblock(bytes.NewReader(image), test.diskSize, test.firstLBA, test.lastLBA)
			if err != nil || report.Status != test.wantState || report.BlockDeviceOpened || report.MutationsPerformed || report.MountPerformed {
				t.Fatalf("bounds result=%+v err=%v want status %q", report, err, test.wantState)
			}
		})
	}
	if _, err := InspectExtSuperblock(bytes.NewReader(image), -1, 40, 49); err == nil {
		t.Fatal("negative disk size accepted")
	}
}

func TestInspectExtSuperblockCombines64BitCountersWithinLargeSparseImage(t *testing.T) {
	const sectors = uint64(10_000_000_000)
	const firstLBA = uint64(40)
	lastLBA := sectors - 34
	metadata := make([]byte, extSuperblockBytes)
	putExtSuperblockFields(metadata, extFixture{
		blockCount:      3,
		blockCountHigh:  1,
		freeBlocks:      5,
		blockSizeLog:    0,
		state:           1,
		revision:        1,
		featureIncompat: extIncompat64Bit,
	})
	reader := fixedMetadataReader{offset: int64(firstLBA*logicalSectorBytes + extSuperblockOffset), data: metadata}
	imageSize := int64(sectors * logicalSectorBytes)
	report, err := InspectExtSuperblock(reader, imageSize, firstLBA, lastLBA)
	if err != nil {
		t.Fatal(err)
	}
	wantBlocks := uint64(1)<<32 | 3
	if report.Status != ExtStatusCandidate || report.BlockCount != wantBlocks || report.FilesystemBytes != wantBlocks*1024 {
		t.Fatalf("64-bit block counters not parsed safely: %+v", report)
	}
}

type extFixture struct {
	blockCount      uint32
	freeBlocks      uint32
	blockSizeLog    uint32
	state           uint16
	revision        uint32
	featureIncompat uint32
	featureROCompat uint32
	blockCountHigh  uint32
	freeBlocksHigh  uint32
}

func putExtSuperblock(image []byte, partitionFirstLBA uint64, fixture extFixture) {
	const superblockBytes = 1024
	start := int(partitionFirstLBA*logicalSectorBytes + 1024)
	putExtSuperblockFields(image[start:start+superblockBytes], fixture)
}

func putExtSuperblockFields(superblock []byte, fixture extFixture) {
	binary.LittleEndian.PutUint32(superblock[0:4], 4)
	binary.LittleEndian.PutUint32(superblock[4:8], fixture.blockCount)
	binary.LittleEndian.PutUint32(superblock[12:16], fixture.freeBlocks)
	binary.LittleEndian.PutUint32(superblock[0x150:0x154], fixture.blockCountHigh)
	binary.LittleEndian.PutUint32(superblock[0x158:0x15c], fixture.freeBlocksHigh)
	if fixture.blockSizeLog == 0 {
		binary.LittleEndian.PutUint32(superblock[20:24], 1)
	}
	binary.LittleEndian.PutUint32(superblock[24:28], fixture.blockSizeLog)
	binary.LittleEndian.PutUint32(superblock[32:36], fixture.blockCount)
	binary.LittleEndian.PutUint32(superblock[40:44], 4)
	binary.LittleEndian.PutUint16(superblock[56:58], 0xef53)
	binary.LittleEndian.PutUint16(superblock[58:60], fixture.state)
	binary.LittleEndian.PutUint32(superblock[76:80], fixture.revision)
	binary.LittleEndian.PutUint32(superblock[92:96], 4)
	binary.LittleEndian.PutUint32(superblock[96:100], fixture.featureIncompat)
	binary.LittleEndian.PutUint32(superblock[100:104], fixture.featureROCompat)
	copy(superblock[104:120], []byte("fixture-ext-uuid!"))
	copy(superblock[120:136], []byte("EXT4_PRIVATE_LABEL"))
}

type fixedMetadataReader struct {
	offset int64
	data   []byte
}

func (reader fixedMetadataReader) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset != reader.offset || len(buffer) != len(reader.data) {
		return 0, errors.New("unexpected metadata read")
	}
	return copy(buffer, reader.data), nil
}

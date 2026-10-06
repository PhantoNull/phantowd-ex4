// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
)

const (
	extSuperblockBytes          = 1024
	extSuperblockOffset         = 1024
	extMagic                    = 0xef53
	extMaxBlockSizeLog          = 6
	extIncompatRecover          = 0x0004
	extIncompat64Bit            = 0x0080
	extROCompatMetadataChecksum = 0x0400
	extCRC32CChecksumType       = 1
	extChecksumOffset           = 0x3fc
)

type ExtStatus string

const (
	ExtStatusCandidate   ExtStatus = "ext-superblock-candidate"
	ExtStatusNotFound    ExtStatus = "not-ext-superblock"
	ExtStatusDamaged     ExtStatus = "damaged"
	ExtStatusUnsupported ExtStatus = "unsupported"
)

// ExtReport is a narrow observation of one ext-family superblock. A candidate
// is not a filesystem-integrity, WD-layout, or mount-safety determination.
type ExtReport struct {
	Format                        string    `json:"format"`
	SchemaVersion                 int       `json:"schema_version"`
	Status                        ExtStatus `json:"status"`
	FilesystemFamily              string    `json:"filesystem_family"`
	PartitionFirstLBA             uint64    `json:"partition_first_lba"`
	PartitionLastLBA              uint64    `json:"partition_last_lba"`
	DiskSectors                   uint64    `json:"disk_sectors"`
	PartitionBytes                uint64    `json:"partition_bytes"`
	BlockSizeBytes                uint64    `json:"block_size_bytes,omitempty"`
	BlockCount                    uint64    `json:"block_count,omitempty"`
	FreeBlockCount                uint64    `json:"free_block_count,omitempty"`
	FilesystemBytes               uint64    `json:"filesystem_bytes,omitempty"`
	FeatureCompat                 uint32    `json:"feature_compat,omitempty"`
	FeatureIncompat               uint32    `json:"feature_incompat,omitempty"`
	FeatureROCompat               uint32    `json:"feature_ro_compat,omitempty"`
	FilesystemIdentityFingerprint string    `json:"filesystem_identity_fingerprint,omitempty"`
	FilesystemState               string    `json:"filesystem_state,omitempty"`
	CleanUnmount                  bool      `json:"clean_unmount_flag"`
	NeedsJournalRecovery          bool      `json:"needs_journal_recovery"`
	SuperblockChecksumStatus      string    `json:"superblock_checksum_status"`
	RawIdentityRedacted           bool      `json:"raw_identity_redacted"`
	ImageMetadataRead             bool      `json:"image_metadata_read"`
	BlockDeviceOpened             bool      `json:"block_device_opened"`
	MutationsPerformed            bool      `json:"mutations_performed"`
	MountPerformed                bool      `json:"mount_performed"`
	Findings                      []string  `json:"findings"`
	Limitations                   []string  `json:"limitations"`
}

// InspectExtSuperblock reads the ext-family superblock at the standard
// 1024-byte offset within a caller-identified partition in a regular raw image.
// It never reads file data or validates metadata beyond the selected
// superblock fields and its checksum when metadata_csum is advertised; it
// never mounts or mutates the image.
func InspectExtSuperblock(image io.ReaderAt, imageSize int64, firstLBA, lastLBA uint64) (ExtReport, error) {
	report := newExtReport(firstLBA, lastLBA)
	if image == nil || imageSize < 0 {
		return report, errors.New("invalid disk-image reader or size")
	}
	if imageSize%logicalSectorBytes != 0 {
		report.Status = ExtStatusDamaged
		report.Findings = []string{"image size is not aligned to the supported 512-byte logical sector size"}
		return report, nil
	}
	sectors := uint64(imageSize / logicalSectorBytes)
	report.DiskSectors = sectors
	if firstLBA > lastLBA || lastLBA >= sectors {
		report.Status = ExtStatusDamaged
		report.Findings = []string{"partition bounds are inconsistent with the supplied image"}
		return report, nil
	}
	partitionSectors := lastLBA - firstLBA + 1
	report.PartitionBytes = partitionSectors * logicalSectorBytes
	if report.PartitionBytes < extSuperblockOffset+extSuperblockBytes {
		report.Status = ExtStatusUnsupported
		report.Findings = []string{"partition is too small to contain the standard ext superblock"}
		return report, nil
	}
	if firstLBA > uint64(math.MaxInt64-extSuperblockOffset-extSuperblockBytes)/logicalSectorBytes {
		report.Status = ExtStatusDamaged
		report.Findings = []string{"superblock offset exceeds the supported image range"}
		return report, nil
	}

	superblock := make([]byte, extSuperblockBytes)
	if err := readAt(image, superblock, firstLBA*logicalSectorBytes+extSuperblockOffset, imageSize); err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	if binary.LittleEndian.Uint16(superblock[0x38:0x3a]) != extMagic {
		report.Status = ExtStatusNotFound
		report.Findings = []string{"no ext-family superblock magic at the standard partition-relative offset"}
		return report, nil
	}
	report.FilesystemFamily = "ext-family"

	revision := binary.LittleEndian.Uint32(superblock[0x4c:0x50])
	if revision > 1 {
		return unsupportedExt(report, "ext superblock revision is not supported by this bounded reader"), nil
	}
	blockSizeLog := binary.LittleEndian.Uint32(superblock[0x18:0x1c])
	if blockSizeLog > extMaxBlockSizeLog {
		return unsupportedExt(report, "ext block-size exponent is outside the parser's safe range"), nil
	}
	blockSize := uint64(1) << (10 + blockSizeLog)
	firstDataBlock := binary.LittleEndian.Uint32(superblock[0x14:0x18])
	if blockSize == 1024 && firstDataBlock == 0 {
		return damagedExt(report, "1 KiB ext filesystem has an invalid first data block"), nil
	}
	blocksPerGroup := binary.LittleEndian.Uint32(superblock[0x20:0x24])
	inodesPerGroup := binary.LittleEndian.Uint32(superblock[0x28:0x2c])
	if blocksPerGroup == 0 || inodesPerGroup == 0 {
		return damagedExt(report, "ext superblock has zero block-group geometry"), nil
	}

	report.BlockSizeBytes = blockSize
	if revision == 1 {
		report.FeatureCompat = binary.LittleEndian.Uint32(superblock[0x5c:0x60])
		report.FeatureIncompat = binary.LittleEndian.Uint32(superblock[0x60:0x64])
		report.FeatureROCompat = binary.LittleEndian.Uint32(superblock[0x64:0x68])
	}
	if report.FeatureROCompat&extROCompatMetadataChecksum != 0 {
		if superblock[0x175] != extCRC32CChecksumType {
			report.SuperblockChecksumStatus = "unsupported-algorithm"
			return unsupportedExt(report, "ext superblock declares an unsupported checksum algorithm"), nil
		}
		if binary.LittleEndian.Uint32(superblock[extChecksumOffset:extChecksumOffset+4]) != extSuperblockChecksum(superblock) {
			report.SuperblockChecksumStatus = "invalid"
			return damagedExt(report, "ext superblock metadata checksum does not match"), nil
		}
		report.SuperblockChecksumStatus = "valid"
	} else {
		report.SuperblockChecksumStatus = "not-advertised-or-unknown"
	}
	blockCount := uint64(binary.LittleEndian.Uint32(superblock[0x04:0x08]))
	freeBlockCount := uint64(binary.LittleEndian.Uint32(superblock[0x0c:0x10]))
	if revision == 1 {
		if report.FeatureIncompat&extIncompat64Bit != 0 {
			blockCount |= uint64(binary.LittleEndian.Uint32(superblock[0x150:0x154])) << 32
			freeBlockCount |= uint64(binary.LittleEndian.Uint32(superblock[0x158:0x15c])) << 32
		} else if binary.LittleEndian.Uint32(superblock[0x150:0x154]) != 0 || binary.LittleEndian.Uint32(superblock[0x158:0x15c]) != 0 {
			return damagedExt(report, "ext high block counters are set without the 64-bit feature"), nil
		}
	}
	if blockCount == 0 || freeBlockCount > blockCount || uint64(firstDataBlock) >= blockCount ||
		blockCount > report.PartitionBytes/blockSize {
		return damagedExt(report, "ext block counts are inconsistent with the partition bounds"), nil
	}
	report.BlockCount = blockCount
	report.FreeBlockCount = freeBlockCount
	report.FilesystemBytes = blockCount * blockSize

	state := binary.LittleEndian.Uint16(superblock[0x3a:0x3c])
	switch {
	case state&0x0002 != 0:
		report.FilesystemState = "errors-recorded"
	case state&0x0001 != 0:
		report.FilesystemState = "clean-unmount-flag-set"
		report.CleanUnmount = true
	default:
		report.FilesystemState = "not-marked-clean"
	}
	report.NeedsJournalRecovery = report.FeatureIncompat&extIncompatRecover != 0
	if revision == 1 && !allZero(superblock[0x68:0x78]) {
		report.FilesystemIdentityFingerprint = fingerprint("phantowd-ext-uuid-v1\n", superblock[0x68:0x78])
	}
	report.Status = ExtStatusCandidate
	report.Findings = []string{"ext-family superblock fields are structurally plausible; filesystem integrity, WD compatibility and mount safety are unqualified"}
	return report, nil
}

func extSuperblockChecksum(superblock []byte) uint32 {
	return ^crc32.Update(0, crc32.MakeTable(crc32.Castagnoli), superblock[:extChecksumOffset])
}

func newExtReport(firstLBA, lastLBA uint64) ExtReport {
	return ExtReport{
		Format:                   "phantowd-ext-superblock-inspection",
		SchemaVersion:            1,
		Status:                   ExtStatusUnsupported,
		FilesystemFamily:         "unknown",
		PartitionFirstLBA:        firstLBA,
		PartitionLastLBA:         lastLBA,
		SuperblockChecksumStatus: "not-validated",
		RawIdentityRedacted:      true,
		ImageMetadataRead:        false,
		BlockDeviceOpened:        false,
		MutationsPerformed:       false,
		MountPerformed:           false,
		Findings:                 []string{},
		Limitations: []string{
			"only the 1024-byte ext-family superblock at partition offset 1024 is inspected",
			"the ext superblock checksum is checked only when metadata_csum with CRC32C is advertised; no other filesystem checksums, metadata, or file data are read",
			"a structurally plausible superblock is not proof of filesystem health, a supported WD layout, or safe mounting",
			"nonzero dynamic-revision filesystem UUIDs are replaced with deterministic SHA-256 fingerprints that are not authenticity checks",
			"input must be a regular local image file; no block device is opened, mounted, or modified",
		},
	}
}

func damagedExt(report ExtReport, finding string) ExtReport {
	report.Status = ExtStatusDamaged
	report.Findings = []string{finding}
	return report
}

func unsupportedExt(report ExtReport, finding string) ExtReport {
	report.Status = ExtStatusUnsupported
	report.Findings = []string{finding}
	return report
}

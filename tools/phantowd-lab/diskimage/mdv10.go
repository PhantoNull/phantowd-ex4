// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

type MDV10Status string

const (
	MDV10StatusCandidate   MDV10Status = "md-v1.0-superblock-candidate"
	MDV10StatusNotFound    MDV10Status = "no-md-v1.0-superblock"
	MDV10StatusDamaged     MDV10Status = "damaged"
	MDV10StatusUnsupported MDV10Status = "unsupported"
)

// MDV10Report is a bounded, read-only observation of one native Linux MD 1.0
// component superblock located relative to a caller-selected partition range.
// It does not establish array completeness, health, or WD-layout compatibility.
type MDV10Report struct {
	Format                     string      `json:"format"`
	SchemaVersion              int         `json:"schema_version"`
	Status                     MDV10Status `json:"status"`
	MetadataVersion            string      `json:"metadata_version"`
	PartitionFirstLBA          uint64      `json:"partition_first_lba"`
	PartitionLastLBA           uint64      `json:"partition_last_lba"`
	DiskSectors                uint64      `json:"disk_sectors"`
	PartitionBytes             uint64      `json:"partition_bytes"`
	SuperblockOffsetBytes      uint64      `json:"superblock_offset_bytes"`
	ArrayLevel                 int32       `json:"array_level"`
	ArrayLayout                uint32      `json:"array_layout"`
	ArraySizeSectors           uint64      `json:"array_size_sectors"`
	ChunkSizeSectors           uint32      `json:"chunk_size_sectors"`
	RAIDDisks                  uint32      `json:"raid_disks"`
	MaxDevices                 uint32      `json:"max_devices"`
	MemberNumber               uint32      `json:"member_number"`
	MemberRole                 uint16      `json:"member_role"`
	MemberRoleDescription      string      `json:"member_role_description,omitempty"`
	FeatureMap                 uint32      `json:"feature_map"`
	Events                     uint64      `json:"events"`
	ComponentDataOffsetSectors uint64      `json:"component_data_offset_sectors"`
	ComponentDataSectors       uint64      `json:"component_data_sectors"`
	SuperblockChecksumStatus   string      `json:"superblock_checksum_status"`
	ArrayIdentityFingerprint   string      `json:"array_identity_fingerprint,omitempty"`
	MemberIdentityFingerprint  string      `json:"member_identity_fingerprint,omitempty"`
	RawIdentityRedacted        bool        `json:"raw_identity_redacted"`
	WDCompatibility            string      `json:"wd_compatibility"`
	ImageMetadataRead          bool        `json:"image_metadata_read"`
	BlockDeviceOpened          bool        `json:"block_device_opened"`
	MutationsPerformed         bool        `json:"mutations_performed"`
	AssemblyPerformed          bool        `json:"assembly_performed"`
	MountPerformed             bool        `json:"mount_performed"`
	Findings                   []string    `json:"findings"`
	Limitations                []string    `json:"limitations"`
}

// InspectMDV10Superblock reads only the bounded Linux MD v1 superblock and
// role array from the standard metadata 1.0 end-of-component location inside
// one partition in a caller-supplied regular-file image. It never opens a
// block device, assembles, mounts, or modifies the image.
func InspectMDV10Superblock(image io.ReaderAt, imageSize int64, firstLBA, lastLBA uint64) (MDV10Report, error) {
	report := newMDV10Report(firstLBA, lastLBA)
	if image == nil || imageSize < 0 {
		return report, errors.New("invalid disk-image reader or size")
	}
	if imageSize%logicalSectorBytes != 0 {
		return damagedMDV10(report, "image size is not aligned to the supported 512-byte logical sector size"), nil
	}

	diskSectors := uint64(imageSize / logicalSectorBytes)
	report.DiskSectors = diskSectors
	if firstLBA > lastLBA || lastLBA >= diskSectors {
		return damagedMDV10(report, "partition bounds are inconsistent with the supplied image"), nil
	}
	partitionSectors := lastLBA - firstLBA + 1
	report.PartitionBytes = partitionSectors * logicalSectorBytes
	if partitionSectors < 24 {
		return unsupportedMDV10(report, "partition is too small to contain a standard MD v1.0 superblock"), nil
	}

	// Linux mdadm's metadata 1.0 placement rounds (component sectors - 16)
	// down to a four-kibibyte boundary, placing the superblock 8-12 KiB from
	// the end of this component. firstLBA is the containing disk-image offset.
	superSector := (partitionSectors - 16) &^ uint64(7)
	metadataStart := superSector * logicalSectorBytes
	if firstLBA > uint64(math.MaxInt64)/logicalSectorBytes ||
		metadataStart > uint64(math.MaxInt64)-firstLBA*logicalSectorBytes {
		return damagedMDV10(report, "superblock offset exceeds the supported image range"), nil
	}
	base := firstLBA*logicalSectorBytes + metadataStart
	if metadataStart > report.PartitionBytes || uint64(mdV1FixedBytes) > report.PartitionBytes-metadataStart {
		return damagedMDV10(report, "MD v1.0 superblock range exceeds its containing partition"), nil
	}
	report.SuperblockOffsetBytes = base

	fixed := make([]byte, mdV1FixedBytes)
	if err := readAt(image, fixed, base, imageSize); err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	if binary.LittleEndian.Uint32(fixed[0:4]) != mdV1Magic {
		report.Status = MDV10StatusNotFound
		report.Findings = []string{"no Linux MD superblock magic at the standard metadata 1.0 end-of-component offset"}
		return report, nil
	}
	if binary.LittleEndian.Uint32(fixed[4:8]) != 1 {
		return unsupportedMDV10(report, "MD superblock is not version 1"), nil
	}

	maxDevices := binary.LittleEndian.Uint32(fixed[mdV1MaxDevicesField : mdV1MaxDevicesField+4])
	if maxDevices == 0 || maxDevices > mdV1MaxDevices {
		return damagedMDV10(report, "MD v1 role-array length exceeds the bounded superblock size"), nil
	}
	metadataBytes := mdV1FixedBytes + uint64(maxDevices)*2
	if metadataBytes > mdV1MaximumBytes || metadataBytes > report.PartitionBytes ||
		metadataStart > report.PartitionBytes-metadataBytes {
		return damagedMDV10(report, "MD v1 role array extends beyond its containing partition"), nil
	}
	superblock := make([]byte, metadataBytes)
	copy(superblock, fixed)
	if len(superblock) > len(fixed) {
		if err := readAt(image, superblock[len(fixed):], base+mdV1FixedBytes, imageSize); err != nil {
			return report, err
		}
	}
	storedChecksum := binary.LittleEndian.Uint32(superblock[mdV1ChecksumField : mdV1ChecksumField+4])
	if mdV1Checksum(superblock) != storedChecksum {
		report.SuperblockChecksumStatus = "invalid"
		return damagedMDV10(report, "MD v1 superblock checksum does not match"), nil
	}
	report.SuperblockChecksumStatus = "valid"
	if binary.LittleEndian.Uint64(superblock[mdV1SuperOffsetField:mdV1SuperOffsetField+8]) != superSector {
		return unsupportedMDV10(report, "MD v1 superblock at this location does not declare metadata version 1.0"), nil
	}

	report.MetadataVersion = "1.0"
	report.FeatureMap = binary.LittleEndian.Uint32(superblock[8:12])
	report.ArrayLevel = int32(binary.LittleEndian.Uint32(superblock[72:76]))
	report.ArrayLayout = binary.LittleEndian.Uint32(superblock[76:80])
	report.ArraySizeSectors = binary.LittleEndian.Uint64(superblock[80:88])
	report.ChunkSizeSectors = binary.LittleEndian.Uint32(superblock[88:92])
	report.RAIDDisks = binary.LittleEndian.Uint32(superblock[92:96])
	report.ComponentDataOffsetSectors = binary.LittleEndian.Uint64(superblock[128:136])
	report.ComponentDataSectors = binary.LittleEndian.Uint64(superblock[136:144])
	report.MemberNumber = binary.LittleEndian.Uint32(superblock[160:164])
	report.MaxDevices = maxDevices
	report.Events = binary.LittleEndian.Uint64(superblock[200:208])

	if report.ArraySizeSectors == 0 || report.RAIDDisks == 0 || report.RAIDDisks > maxDevices ||
		report.MemberNumber >= maxDevices {
		return damagedMDV10(report, "MD array size, member number, and device counts are inconsistent with the bounded role array"), nil
	}
	if report.ComponentDataOffsetSectors > superSector ||
		report.ComponentDataSectors == 0 ||
		report.ComponentDataSectors > superSector-report.ComponentDataOffsetSectors {
		return damagedMDV10(report, "MD component data extent overlaps metadata or exceeds the containing partition"), nil
	}

	roleOffset := mdV1RolesOffset + report.MemberNumber*2
	role := binary.LittleEndian.Uint16(superblock[roleOffset : roleOffset+2])
	report.MemberRole = role
	switch {
	case role < uint16(report.RAIDDisks):
		report.MemberRoleDescription = "active-slot"
	case role == mdV1RoleSpare:
		report.MemberRoleDescription = "spare"
	case role == mdV1RoleFaulty:
		report.MemberRoleDescription = "faulty"
	case role == mdV1RoleJournal:
		report.MemberRoleDescription = "journal"
	default:
		return unsupportedMDV10(report, "MD member role uses an unrecognized reserved value"), nil
	}
	if !allZero(superblock[16:32]) {
		report.ArrayIdentityFingerprint = fingerprint("phantowd-md-array-v1\n", superblock[16:32])
	}
	if !allZero(superblock[168:184]) {
		report.MemberIdentityFingerprint = fingerprint("phantowd-md-member-v1\n", superblock[168:184])
	}
	report.Status = MDV10StatusCandidate
	report.Findings = []string{"one generic MD v1.0 component superblock is structurally plausible; array-wide consistency, filesystem integrity, WD compatibility and assembly safety are unqualified"}
	return report, nil
}

func newMDV10Report(firstLBA, lastLBA uint64) MDV10Report {
	return MDV10Report{
		Format:                   "phantowd-md-v1.0-superblock-inspection",
		SchemaVersion:            1,
		Status:                   MDV10StatusUnsupported,
		PartitionFirstLBA:        firstLBA,
		PartitionLastLBA:         lastLBA,
		SuperblockChecksumStatus: "not-validated",
		RawIdentityRedacted:      true,
		WDCompatibility:          "unqualified",
		Findings:                 []string{},
		Limitations: []string{
			"only one generic Linux MD v1.0 component superblock and bounded role array are read; other component metadata and live array state are not inspected",
			"a plausible component superblock does not establish cross-member consistency, array health, filesystem integrity, WD compatibility, or safe assembly",
			"raw array/member UUIDs and host-supplied paths are not returned; identity fingerprints are not authenticity checks",
			"input must be a regular local image file; no block device is opened, no array is assembled, no filesystem is mounted, and no image is modified",
		},
	}
}

func damagedMDV10(report MDV10Report, finding string) MDV10Report {
	report.Status = MDV10StatusDamaged
	report.Findings = []string{finding}
	return report
}

func unsupportedMDV10(report MDV10Report, finding string) MDV10Report {
	report.Status = MDV10StatusUnsupported
	report.Findings = []string{finding}
	return report
}

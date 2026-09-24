// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const (
	mdV1Magic                      = 0xa92b4efc
	mdV1FixedBytes                 = 256
	mdV1MaximumBytes               = 4096
	mdV1MaxDevices                 = (mdV1MaximumBytes - mdV1FixedBytes) / 2
	mdV12SuperblockOffset          = 4096
	mdV12SuperOffsetSectors        = 8
	mdV1SuperOffsetField           = 144
	mdV1ChecksumField              = 216
	mdV1MaxDevicesField            = 220
	mdV1RolesOffset                = mdV1FixedBytes
	mdV1RoleJournal         uint16 = 0xfffd
	mdV1RoleFaulty          uint16 = 0xfffe
	mdV1RoleSpare           uint16 = 0xffff
)

type MDStatus string

const (
	MDStatusCandidate   MDStatus = "md-v1.2-superblock-candidate"
	MDStatusNotFound    MDStatus = "no-md-v1.2-superblock"
	MDStatusDamaged     MDStatus = "damaged"
	MDStatusUnsupported MDStatus = "unsupported"
)

// MDV12Report contains a narrow, read-only observation of one native Linux
// MD 1.2 component superblock. It is not an array-assembly or WD-compatibility
// determination.
type MDV12Report struct {
	Format                     string   `json:"format"`
	SchemaVersion              int      `json:"schema_version"`
	Status                     MDStatus `json:"status"`
	MetadataVersion            string   `json:"metadata_version"`
	PartitionFirstLBA          uint64   `json:"partition_first_lba"`
	PartitionLastLBA           uint64   `json:"partition_last_lba"`
	DiskSectors                uint64   `json:"disk_sectors"`
	PartitionBytes             uint64   `json:"partition_bytes"`
	ArrayLevel                 int32    `json:"array_level"`
	RAIDDisks                  uint32   `json:"raid_disks"`
	MaxDevices                 uint32   `json:"max_devices"`
	MemberNumber               uint32   `json:"member_number"`
	MemberRole                 uint16   `json:"member_role"`
	MemberRoleDescription      string   `json:"member_role_description,omitempty"`
	FeatureMap                 uint32   `json:"feature_map"`
	Events                     uint64   `json:"events"`
	ComponentDataOffsetSectors uint64   `json:"component_data_offset_sectors"`
	ComponentDataSectors       uint64   `json:"component_data_sectors"`
	SuperblockChecksumStatus   string   `json:"superblock_checksum_status"`
	ArrayIdentityFingerprint   string   `json:"array_identity_fingerprint,omitempty"`
	MemberIdentityFingerprint  string   `json:"member_identity_fingerprint,omitempty"`
	RawIdentityRedacted        bool     `json:"raw_identity_redacted"`
	WDCompatibility            string   `json:"wd_compatibility"`
	ImageMetadataRead          bool     `json:"image_metadata_read"`
	BlockDeviceOpened          bool     `json:"block_device_opened"`
	MutationsPerformed         bool     `json:"mutations_performed"`
	AssemblyPerformed          bool     `json:"assembly_performed"`
	MountPerformed             bool     `json:"mount_performed"`
	Findings                   []string `json:"findings"`
	Limitations                []string `json:"limitations"`
}

// InspectMDV12Superblock reads only the fixed and bounded variable portions of
// a Linux MD 1.2 superblock from a caller-identified partition in a regular
// raw image. It never opens a block device, assembles an array, mounts, or
// mutates the supplied image.
func InspectMDV12Superblock(image io.ReaderAt, imageSize int64, firstLBA, lastLBA uint64) (MDV12Report, error) {
	report := newMDV12Report(firstLBA, lastLBA)
	if image == nil || imageSize < 0 {
		return report, errors.New("invalid disk-image reader or size")
	}
	if imageSize%logicalSectorBytes != 0 {
		return damagedMD(report, "image size is not aligned to the supported 512-byte logical sector size"), nil
	}

	sectors := uint64(imageSize / logicalSectorBytes)
	report.DiskSectors = sectors
	if firstLBA > lastLBA || lastLBA >= sectors {
		return damagedMD(report, "partition bounds are inconsistent with the supplied image"), nil
	}
	partitionSectors := lastLBA - firstLBA + 1
	report.PartitionBytes = partitionSectors * logicalSectorBytes
	if report.PartitionBytes < mdV12SuperblockOffset+mdV1FixedBytes {
		return unsupportedMD(report, "partition is too small to contain an MD 1.2 superblock"), nil
	}
	if firstLBA > uint64(math.MaxInt64-mdV12SuperblockOffset-mdV1MaximumBytes)/logicalSectorBytes {
		return damagedMD(report, "superblock offset exceeds the supported image range"), nil
	}

	base := firstLBA*logicalSectorBytes + mdV12SuperblockOffset
	fixed := make([]byte, mdV1FixedBytes)
	if err := readAt(image, fixed, base, imageSize); err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	if binary.LittleEndian.Uint32(fixed[0:4]) != mdV1Magic {
		report.Status = MDStatusNotFound
		report.Findings = []string{"no Linux MD superblock magic at the standard metadata 1.2 partition-relative offset"}
		return report, nil
	}
	if binary.LittleEndian.Uint32(fixed[4:8]) != 1 {
		return unsupportedMD(report, "MD superblock is not version 1"), nil
	}

	maxDevices := binary.LittleEndian.Uint32(fixed[mdV1MaxDevicesField : mdV1MaxDevicesField+4])
	if maxDevices == 0 || maxDevices > mdV1MaxDevices {
		return damagedMD(report, "MD v1 role-array length exceeds the bounded superblock size"), nil
	}
	metadataBytes := mdV1FixedBytes + uint64(maxDevices)*2
	if metadataBytes > uint64(report.PartitionBytes-mdV12SuperblockOffset) {
		return damagedMD(report, "MD v1 role array extends beyond its containing partition"), nil
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
		return damagedMD(report, "MD v1 superblock checksum does not match"), nil
	}
	report.SuperblockChecksumStatus = "valid"

	superOffset := binary.LittleEndian.Uint64(superblock[mdV1SuperOffsetField : mdV1SuperOffsetField+8])
	if superOffset != mdV12SuperOffsetSectors {
		return unsupportedMD(report, "MD v1 superblock at this location does not declare metadata version 1.2"), nil
	}

	report.MetadataVersion = "1.2"
	report.FeatureMap = binary.LittleEndian.Uint32(superblock[8:12])
	report.ArrayLevel = int32(binary.LittleEndian.Uint32(superblock[72:76]))
	report.RAIDDisks = binary.LittleEndian.Uint32(superblock[92:96])
	report.ComponentDataOffsetSectors = binary.LittleEndian.Uint64(superblock[128:136])
	report.ComponentDataSectors = binary.LittleEndian.Uint64(superblock[136:144])
	report.MemberNumber = binary.LittleEndian.Uint32(superblock[160:164])
	report.MaxDevices = maxDevices
	report.Events = binary.LittleEndian.Uint64(superblock[200:208])

	if report.RAIDDisks == 0 || report.RAIDDisks > maxDevices {
		return damagedMD(report, "MD RAID disk count is inconsistent with the bounded role array"), nil
	}
	if report.MemberNumber >= maxDevices {
		return damagedMD(report, "MD member number is outside the bounded role array"), nil
	}
	metadataEndSectors := mdV12SuperOffsetSectors + (metadataBytes+logicalSectorBytes-1)/logicalSectorBytes
	if report.ComponentDataSectors == 0 || report.ComponentDataOffsetSectors < metadataEndSectors ||
		report.ComponentDataOffsetSectors > partitionSectors ||
		report.ComponentDataSectors > partitionSectors-report.ComponentDataOffsetSectors {
		return damagedMD(report, "MD component data extent exceeds the containing partition"), nil
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
		return unsupportedMD(report, "MD member role uses an unrecognized reserved value"), nil
	}
	if !allZero(superblock[16:32]) {
		report.ArrayIdentityFingerprint = fingerprint("phantowd-md-array-v1\n", superblock[16:32])
	}
	if !allZero(superblock[168:184]) {
		report.MemberIdentityFingerprint = fingerprint("phantowd-md-member-v1\n", superblock[168:184])
	}
	report.Status = MDStatusCandidate
	report.Findings = []string{"one generic MD v1.2 component superblock is structurally plausible; array-wide consistency, filesystem integrity, WD compatibility and assembly safety are unqualified"}
	return report, nil
}

func mdV1Checksum(superblock []byte) uint32 {
	copyForChecksum := append([]byte(nil), superblock...)
	clear(copyForChecksum[mdV1ChecksumField : mdV1ChecksumField+4])
	var sum uint64
	for offset := 0; offset+4 <= len(copyForChecksum); offset += 4 {
		sum += uint64(binary.LittleEndian.Uint32(copyForChecksum[offset : offset+4]))
	}
	if len(copyForChecksum)%4 == 2 {
		sum += uint64(binary.LittleEndian.Uint16(copyForChecksum[len(copyForChecksum)-2:]))
	}
	return uint32(sum) + uint32(sum>>32)
}

func newMDV12Report(firstLBA, lastLBA uint64) MDV12Report {
	return MDV12Report{
		Format:                   "phantowd-md-v1.2-superblock-inspection",
		SchemaVersion:            1,
		Status:                   MDStatusUnsupported,
		PartitionFirstLBA:        firstLBA,
		PartitionLastLBA:         lastLBA,
		SuperblockChecksumStatus: "not-validated",
		RawIdentityRedacted:      true,
		WDCompatibility:          "unqualified",
		Findings:                 []string{},
		Limitations: []string{
			"only one Linux MD v1.2 component superblock and its bounded role array are read; other MD metadata versions and locations are not inspected",
			"a plausible component superblock does not establish cross-member consistency, array health, filesystem integrity, WD compatibility, or safe assembly",
			"raw array/member UUIDs and host-supplied paths are not returned; identity fingerprints are not authenticity checks",
			"input must be a regular local image file; no block device is opened, no array is assembled, no filesystem is mounted, and no image is modified",
		},
	}
}

func damagedMD(report MDV12Report, finding string) MDV12Report {
	report.Status = MDStatusDamaged
	report.Findings = []string{finding}
	return report
}

func unsupportedMD(report MDV12Report, finding string) MDV12Report {
	report.Status = MDStatusUnsupported
	report.Findings = []string{finding}
	return report
}

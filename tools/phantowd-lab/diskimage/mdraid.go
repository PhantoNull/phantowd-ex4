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

type MDV090Status string

const (
	MDV090StatusCandidate   MDV090Status = "md-v0.90-superblock-candidate"
	MDV090StatusNotFound    MDV090Status = "no-md-v0.90-superblock"
	MDV090StatusDamaged     MDV090Status = "damaged"
	MDV090StatusUnsupported MDV090Status = "unsupported"
)

const (
	mdV090Magic            = 0xa92b4efc
	mdV090SuperblockBytes  = 4096
	mdV090ReservedBytes    = 64 * 1024
	mdV090ChecksumField    = 152
	mdV090MaxDevices       = 27
	mdV090DisksOffsetWords = 128
	mdV090DescriptorWords  = 32
	mdV090DescriptorBytes  = mdV090DescriptorWords * 4
	mdV090ThisDiskOffset   = 992 * 4
	mdV090RoleSpare        = 0xffff
	mdV090RoleFaulty       = 0xfffe
	mdV090RoleJournal      = 0xfffd
	mdV090StateFaulty      = uint32(1 << 0)
	mdV090StateActive      = uint32(1 << 1)
	mdV090StateSync        = uint32(1 << 2)
	mdV090StateRemoved     = uint32(1 << 3)
	mdV090StateWriteMostly = uint32(1 << 9)
)

// MDV090DiskDescriptor is a redacted projection of one fixed array-wide
// descriptor. Major/minor device-node numbers and reserved words are omitted.
// HasNonzeroCoreFields reports whether any of the five defined descriptor
// fields is nonzero, including the redacted major/minor values.
type MDV090DiskDescriptor struct {
	DescriptorIndex      int      `json:"descriptor_index"`
	HasNonzeroCoreFields bool     `json:"has_nonzero_core_fields"`
	MemberNumber         uint32   `json:"member_number"`
	Role                 uint32   `json:"role"`
	State                uint32   `json:"state"`
	StateFlags           []string `json:"state_flags"`
}

// MDV090Report is a bounded, read-only observation of a generic Linux MD
// 0.90 superblock at the standard end-of-component location. It does not
// establish that an array is complete, healthy, or compatible with any WD
// model.
type MDV090Report struct {
	Format                   string                 `json:"format"`
	SchemaVersion            int                    `json:"schema_version"`
	Status                   MDV090Status           `json:"status"`
	MetadataVersion          string                 `json:"metadata_version"`
	WDCompatibility          string                 `json:"wd_compatibility"`
	ComponentBytes           uint64                 `json:"component_bytes"`
	SuperblockOffsetBytes    uint64                 `json:"superblock_offset_bytes"`
	ArrayLevel               int32                  `json:"array_level"`
	NRDisks                  uint32                 `json:"nr_disks"`
	RAIDDisks                uint32                 `json:"raid_disks"`
	MemberNumber             uint32                 `json:"member_number"`
	MemberRole               uint32                 `json:"member_role"`
	MemberRoleDescription    string                 `json:"member_role_description,omitempty"`
	MemberState              uint32                 `json:"member_state"`
	MemberStateFlags         []string               `json:"member_state_flags"`
	DiskDescriptors          []MDV090DiskDescriptor `json:"disk_descriptors"`
	Events                   uint64                 `json:"events"`
	SuperblockChecksumStatus string                 `json:"superblock_checksum_status"`
	ArrayIdentityFingerprint string                 `json:"array_identity_fingerprint,omitempty"`
	RawIdentityRedacted      bool                   `json:"raw_identity_redacted"`
	ImageMetadataRead        bool                   `json:"image_metadata_read"`
	BlockDeviceOpened        bool                   `json:"block_device_opened"`
	MutationsPerformed       bool                   `json:"mutations_performed"`
	AssemblyPerformed        bool                   `json:"assembly_performed"`
	MountPerformed           bool                   `json:"mount_performed"`
	Findings                 []string               `json:"findings"`
	Limitations              []string               `json:"limitations"`
}

// InspectMDV090Component inspects only a regular-file image supplied by the
// caller as one MD component device (typically a partition image). It follows
// the Linux 0.90 end-of-device placement formula and reads exactly one 4096-
// byte superblock. It never opens a block device, assembles, mounts, or writes.
func InspectMDV090Component(image io.ReaderAt, imageSize int64) (MDV090Report, error) {
	report := newMDV090Report(imageSize)
	if image == nil || imageSize < 0 {
		return report, errors.New("invalid component-image reader or size")
	}
	if imageSize%logicalSectorBytes != 0 {
		return damagedMDV090(report, "component image is not aligned to the supported 512-byte logical sector size"), nil
	}
	report.ComponentBytes = uint64(imageSize)
	if imageSize < mdV090ReservedBytes {
		return unsupportedMDV090(report, "component image is smaller than the 64 KiB reserved metadata region"), nil
	}

	// MD_NEW_SIZE_SECTORS rounds the byte length down to a 64 KiB boundary,
	// then reserves the preceding 64 KiB for the superblock and optional data.
	alignedSize := uint64(imageSize) &^ uint64(mdV090ReservedBytes-1)
	if alignedSize < mdV090ReservedBytes {
		return unsupportedMDV090(report, "component image is too small for the standard MD 0.90 superblock placement"), nil
	}
	offset := alignedSize - mdV090ReservedBytes
	if offset+mdV090SuperblockBytes > uint64(imageSize) || offset > math.MaxInt64 {
		return damagedMDV090(report, "calculated MD 0.90 superblock range exceeds the component image"), nil
	}
	report.SuperblockOffsetBytes = offset

	superblock := make([]byte, mdV090SuperblockBytes)
	if err := readAt(image, superblock, offset, imageSize); err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	magic := binary.LittleEndian.Uint32(superblock[0:4])
	if magic != mdV090Magic {
		if binary.BigEndian.Uint32(superblock[0:4]) == mdV090Magic {
			return unsupportedMDV090(report, "big-endian MD 0.90 metadata is not supported by this inspector"), nil
		}
		report.Status = MDV090StatusNotFound
		report.Findings = []string{"no Linux MD 0.90 magic at the standard end-of-component offset"}
		return report, nil
	}
	if binary.LittleEndian.Uint32(superblock[4:8]) != 0 {
		return unsupportedMDV090(report, "MD metadata at the standard legacy offset is not version 0"), nil
	}
	if binary.LittleEndian.Uint32(superblock[8:12]) != 90 {
		return unsupportedMDV090(report, "legacy MD metadata minor version is not exactly 90"), nil
	}

	report.MetadataVersion = "0.90"
	storedChecksum := binary.LittleEndian.Uint32(superblock[mdV090ChecksumField : mdV090ChecksumField+4])
	if mdV090Checksum(superblock) != storedChecksum {
		report.SuperblockChecksumStatus = "invalid"
		return damagedMDV090(report, "MD 0.90 superblock checksum does not match"), nil
	}
	report.SuperblockChecksumStatus = "valid"

	report.ArrayLevel = int32(binary.LittleEndian.Uint32(superblock[28:32]))
	report.NRDisks = binary.LittleEndian.Uint32(superblock[36:40])
	report.RAIDDisks = binary.LittleEndian.Uint32(superblock[40:44])
	report.Events = uint64(binary.LittleEndian.Uint32(superblock[156:160])) |
		uint64(binary.LittleEndian.Uint32(superblock[160:164]))<<32
	report.MemberNumber = binary.LittleEndian.Uint32(superblock[mdV090ThisDiskOffset : mdV090ThisDiskOffset+4])
	report.MemberRole = binary.LittleEndian.Uint32(superblock[mdV090ThisDiskOffset+12 : mdV090ThisDiskOffset+16])
	report.MemberState = binary.LittleEndian.Uint32(superblock[mdV090ThisDiskOffset+16 : mdV090ThisDiskOffset+20])
	report.MemberStateFlags = mdV090StateFlags(report.MemberState)
	report.DiskDescriptors = mdV090DiskDescriptors(superblock)

	if report.NRDisks == 0 || report.NRDisks > mdV090MaxDevices ||
		report.RAIDDisks == 0 || report.RAIDDisks > report.NRDisks ||
		report.MemberNumber >= report.NRDisks {
		return damagedMDV090(report, "MD 0.90 member and array counts are inconsistent with the 27-device metadata limit"), nil
	}
	if report.MemberRole < report.RAIDDisks {
		report.MemberRoleDescription = "raid-slot"
	} else {
		switch report.MemberRole {
		case mdV090RoleSpare:
			report.MemberRoleDescription = "spare-role"
		case mdV090RoleFaulty:
			report.MemberRoleDescription = "faulty-role"
		case mdV090RoleJournal:
			report.MemberRoleDescription = "journal-role"
		default:
			return unsupportedMDV090(report, "MD 0.90 member role uses an unrecognized value"), nil
		}
	}

	arrayUUID := make([]byte, 16)
	copy(arrayUUID[0:4], superblock[20:24])
	copy(arrayUUID[4:8], superblock[52:56])
	copy(arrayUUID[8:12], superblock[56:60])
	copy(arrayUUID[12:16], superblock[60:64])
	if !allZero(arrayUUID) {
		report.ArrayIdentityFingerprint = fingerprint("phantowd-md-v0.90-array\n", arrayUUID)
	}
	report.Status = MDV090StatusCandidate
	report.Findings = []string{"one generic Linux MD 0.90 component superblock is structurally plausible; array-wide consistency, member health, filesystem integrity, WD compatibility, and assembly safety are unqualified"}
	return report, nil
}

// mdV090StateFlags decodes only state bits defined by the Linux 3.2 MD 0.90
// disk descriptor. The raw field is retained so unrecognized bits remain
// observable rather than being silently discarded.
func mdV090StateFlags(state uint32) []string {
	flags := make([]string, 0, 5)
	for _, flag := range []struct {
		mask uint32
		name string
	}{
		{mdV090StateFaulty, "faulty"},
		{mdV090StateActive, "active"},
		{mdV090StateSync, "sync"},
		{mdV090StateRemoved, "removed"},
		{mdV090StateWriteMostly, "write-mostly"},
	} {
		if state&flag.mask != 0 {
			flags = append(flags, flag.name)
		}
	}
	return flags
}

func mdV090DiskDescriptors(superblock []byte) []MDV090DiskDescriptor {
	descriptors := make([]MDV090DiskDescriptor, 0, mdV090MaxDevices)
	for index := 0; index < mdV090MaxDevices; index++ {
		offset := mdV090DisksOffsetWords*4 + index*mdV090DescriptorBytes
		number := binary.LittleEndian.Uint32(superblock[offset : offset+4])
		major := binary.LittleEndian.Uint32(superblock[offset+4 : offset+8])
		minor := binary.LittleEndian.Uint32(superblock[offset+8 : offset+12])
		role := binary.LittleEndian.Uint32(superblock[offset+12 : offset+16])
		state := binary.LittleEndian.Uint32(superblock[offset+16 : offset+20])
		descriptors = append(descriptors, MDV090DiskDescriptor{
			DescriptorIndex:      index,
			HasNonzeroCoreFields: number != 0 || major != 0 || minor != 0 || role != 0 || state != 0,
			MemberNumber:         number,
			Role:                 role,
			State:                state,
			StateFlags:           mdV090StateFlags(state),
		})
	}
	return descriptors
}

func mdV090Checksum(superblock []byte) uint32 {
	var sum uint64
	for offset := 0; offset+4 <= len(superblock); offset += 4 {
		if offset == mdV090ChecksumField {
			continue
		}
		sum += uint64(binary.LittleEndian.Uint32(superblock[offset : offset+4]))
	}
	return uint32(sum) + uint32(sum>>32)
}

func newMDV090Report(imageSize int64) MDV090Report {
	report := MDV090Report{
		Format:                   "phantowd-md-v0.90-component-inspection",
		SchemaVersion:            3,
		Status:                   MDV090StatusUnsupported,
		WDCompatibility:          "unqualified",
		SuperblockChecksumStatus: "not-validated",
		RawIdentityRedacted:      true,
		MemberStateFlags:         []string{},
		DiskDescriptors:          []MDV090DiskDescriptor{},
		Findings:                 []string{},
		Limitations: []string{
			"input must be a regular image of one component device; a whole-disk image is not automatically partitioned or scanned",
			"only one 4096-byte MD 0.90 superblock at the standard end-of-device location is read; optional bitmap bytes and alternate layouts are not inspected",
			"the array-wide 27-entry descriptor table is returned as redacted stored metadata; kernel major/minor fields are omitted, and entries are not reconciled with one another or this_disk",
			"one plausible component does not prove cross-member event agreement, array health, filesystem integrity, WD compatibility, or safe assembly",
			"raw array identity and host-supplied paths are not returned; the identity fingerprint is not an authenticity check",
			"no block device is opened, no array is assembled, no filesystem is mounted, and the input image is never modified",
		},
	}
	if imageSize >= 0 {
		report.ComponentBytes = uint64(imageSize)
	}
	return report
}

func damagedMDV090(report MDV090Report, finding string) MDV090Report {
	report.Status = MDV090StatusDamaged
	report.Findings = []string{finding}
	return report
}

func unsupportedMDV090(report MDV090Report, finding string) MDV090Report {
	report.Status = MDV090StatusUnsupported
	report.Findings = []string{finding}
	return report
}

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
	ArrayLayout                uint32   `json:"array_layout"`
	ArraySizeSectors           uint64   `json:"array_size_sectors"`
	ChunkSizeSectors           uint32   `json:"chunk_size_sectors"`
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
	report.ArrayLayout = binary.LittleEndian.Uint32(superblock[76:80])
	report.ArraySizeSectors = binary.LittleEndian.Uint64(superblock[80:88])
	report.ChunkSizeSectors = binary.LittleEndian.Uint32(superblock[88:92])
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

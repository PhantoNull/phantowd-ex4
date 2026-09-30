// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package mdmetadata contains bounded, read-only Linux MD metadata readers.
// Observations describe generic on-disk structures; they never authorize
// assembly, filesystem mounting, migration, or writes.
package mdmetadata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
)

const (
	logicalSectorBytes   = uint64(512)
	mdV1Magic            = uint32(0xa92b4efc)
	mdV1FixedBytes       = 256
	mdV1MaximumBytes     = 4096
	mdV1MaxDevices       = (mdV1MaximumBytes - mdV1FixedBytes) / 2
	mdV1SuperOffset      = 144
	mdV1ChecksumOffset   = 216
	mdV1MaxDevicesOffset = 220
	mdV1RolesOffset      = mdV1FixedBytes
	mdV1RoleJournal      = uint16(0xfffd)
	mdV1RoleFaulty       = uint16(0xfffe)
	mdV1RoleSpare        = uint16(0xffff)
)

type Status string

const (
	StatusCandidate   Status = "md-v1.0-superblock-candidate"
	StatusNotFound    Status = "no-md-v1.0-superblock"
	StatusDamaged     Status = "damaged"
	StatusUnsupported Status = "unsupported"
)

var ErrUnsafeSource = errors.New("unsafe MD metadata source")

// Partition uses the Linux 512-byte sector convention emitted by the pinned
// partition-table probe. It is a transient, generation-scoped location, not a
// stable identity or a supported-WD-layout claim.
type Partition struct {
	Number   uint32 `json:"-"`
	StartLBA uint64 `json:"-"`
	SizeLBA  uint64 `json:"-"`
}

// Observation deliberately excludes the raw array/member UUIDs. Fingerprints
// are only redaction aids, not authentication or persistent identity.
type Observation struct {
	Status                     Status `json:"-"`
	MetadataVersion            string `json:"-"`
	PartitionNumber            uint32 `json:"-"`
	PartitionFirstLBA          uint64 `json:"-"`
	PartitionLastLBA           uint64 `json:"-"`
	DiskSectors                uint64 `json:"-"`
	PartitionBytes             uint64 `json:"-"`
	SuperblockOffsetBytes      uint64 `json:"-"`
	ArrayLevel                 int32  `json:"-"`
	ArrayLayout                uint32 `json:"-"`
	ArraySizeSectors           uint64 `json:"-"`
	ChunkSizeSectors           uint32 `json:"-"`
	RAIDDisks                  uint32 `json:"-"`
	MaxDevices                 uint32 `json:"-"`
	MemberNumber               uint32 `json:"-"`
	MemberRole                 uint16 `json:"-"`
	MemberRoleDescription      string `json:"-"`
	FeatureMap                 uint32 `json:"-"`
	Events                     uint64 `json:"-"`
	ComponentDataOffsetSectors uint64 `json:"-"`
	ComponentDataSectors       uint64 `json:"-"`
	SuperblockChecksumStatus   string `json:"-"`
	ArrayIdentityFingerprint   string `json:"-"`
	MemberIdentityFingerprint  string `json:"-"`
	MetadataRead               bool   `json:"-"`
}

// InspectPartition reads at most one fixed-size superblock plus the bounded
// MD v1 role array, at the standard metadata 1.0 end-of-partition offset. The
// caller supplies the exact 512-byte GPT geometry already observed elsewhere.
// It does not inspect other partitions, invoke mdadm, assemble, mount or write.
func InspectPartition(source io.ReaderAt, sourceBytes int64, partition Partition) (Observation, error) {
	result := newObservation(partition)
	if source == nil || sourceBytes <= 0 || partition.Number == 0 || partition.SizeLBA == 0 || partition.StartLBA == 0 {
		return result, ErrUnsafeSource
	}
	if sourceBytes%int64(logicalSectorBytes) != 0 {
		return result, ErrUnsafeSource
	}
	diskSectors := uint64(sourceBytes) / logicalSectorBytes
	result.DiskSectors = diskSectors
	if partition.StartLBA > math.MaxUint64-partition.SizeLBA {
		return result, ErrUnsafeSource
	}
	endExclusive := partition.StartLBA + partition.SizeLBA
	if endExclusive > diskSectors || partition.SizeLBA > math.MaxUint64/logicalSectorBytes {
		return result, ErrUnsafeSource
	}
	result.PartitionLastLBA = endExclusive - 1
	result.PartitionBytes = partition.SizeLBA * logicalSectorBytes
	if partition.SizeLBA < 24 {
		return unsupported(result), nil
	}

	// Linux mdadm metadata 1.0 rounds (component sectors - 16) down to an
	// eight-sector boundary; the superblock lies 8-12 KiB before the end.
	superSector := (partition.SizeLBA - 16) &^ uint64(7)
	if partition.StartLBA > uint64(math.MaxInt64)/logicalSectorBytes ||
		superSector > uint64(math.MaxInt64)/logicalSectorBytes-partition.StartLBA {
		return damaged(result), nil
	}
	metadataStartBytes := superSector * logicalSectorBytes
	base := (partition.StartLBA + superSector) * logicalSectorBytes
	if metadataStartBytes > result.PartitionBytes || uint64(mdV1FixedBytes) > result.PartitionBytes-metadataStartBytes {
		return damaged(result), nil
	}
	result.SuperblockOffsetBytes = base

	fixed := make([]byte, mdV1FixedBytes)
	if err := readAt(source, fixed, base, sourceBytes); err != nil {
		return result, err
	}
	result.MetadataRead = true
	if binary.LittleEndian.Uint32(fixed[0:4]) != mdV1Magic {
		result.Status = StatusNotFound
		return result, nil
	}
	if binary.LittleEndian.Uint32(fixed[4:8]) != 1 {
		return unsupported(result), nil
	}
	maxDevices := binary.LittleEndian.Uint32(fixed[mdV1MaxDevicesOffset : mdV1MaxDevicesOffset+4])
	if maxDevices == 0 || maxDevices > mdV1MaxDevices {
		return damaged(result), nil
	}
	metadataBytes := uint64(mdV1FixedBytes) + uint64(maxDevices)*2
	if metadataBytes > mdV1MaximumBytes || metadataBytes > result.PartitionBytes ||
		metadataStartBytes > result.PartitionBytes-metadataBytes {
		return damaged(result), nil
	}
	superblock := make([]byte, int(metadataBytes))
	copy(superblock, fixed)
	if len(superblock) > len(fixed) {
		if err := readAt(source, superblock[len(fixed):], base+mdV1FixedBytes, sourceBytes); err != nil {
			return result, err
		}
	}
	storedChecksum := binary.LittleEndian.Uint32(superblock[mdV1ChecksumOffset : mdV1ChecksumOffset+4])
	if mdV1Checksum(superblock) != storedChecksum {
		result.SuperblockChecksumStatus = "invalid"
		return damaged(result), nil
	}
	result.SuperblockChecksumStatus = "valid"
	if binary.LittleEndian.Uint64(superblock[mdV1SuperOffset:mdV1SuperOffset+8]) != superSector {
		return unsupported(result), nil
	}

	result.MetadataVersion = "1.0"
	result.FeatureMap = binary.LittleEndian.Uint32(superblock[8:12])
	if result.FeatureMap != 0 {
		// Feature semantics are intentionally not inferred from the current
		// generic parser. Preserve the checksum/version observation, but never
		// promote unknown feature combinations to a metadata candidate.
		return unsupported(result), nil
	}
	result.ArrayLevel = int32(binary.LittleEndian.Uint32(superblock[72:76]))
	result.ArrayLayout = binary.LittleEndian.Uint32(superblock[76:80])
	result.ArraySizeSectors = binary.LittleEndian.Uint64(superblock[80:88])
	result.ChunkSizeSectors = binary.LittleEndian.Uint32(superblock[88:92])
	result.RAIDDisks = binary.LittleEndian.Uint32(superblock[92:96])
	result.ComponentDataOffsetSectors = binary.LittleEndian.Uint64(superblock[128:136])
	result.ComponentDataSectors = binary.LittleEndian.Uint64(superblock[136:144])
	result.MemberNumber = binary.LittleEndian.Uint32(superblock[160:164])
	result.MaxDevices = maxDevices
	result.Events = binary.LittleEndian.Uint64(superblock[200:208])
	if result.ArraySizeSectors == 0 || result.RAIDDisks == 0 || result.RAIDDisks > maxDevices || result.MemberNumber >= maxDevices {
		return damaged(result), nil
	}
	if result.ComponentDataOffsetSectors > superSector || result.ComponentDataSectors == 0 ||
		result.ComponentDataSectors > superSector-result.ComponentDataOffsetSectors {
		return damaged(result), nil
	}
	roleOffset := mdV1RolesOffset + result.MemberNumber*2
	result.MemberRole = binary.LittleEndian.Uint16(superblock[roleOffset : roleOffset+2])
	switch {
	case result.MemberRole < uint16(result.RAIDDisks):
		result.MemberRoleDescription = "active-slot"
	case result.MemberRole == mdV1RoleSpare:
		result.MemberRoleDescription = "spare"
	case result.MemberRole == mdV1RoleFaulty:
		result.MemberRoleDescription = "faulty"
	case result.MemberRole == mdV1RoleJournal:
		result.MemberRoleDescription = "journal"
	default:
		return unsupported(result), nil
	}
	if !allZero(superblock[16:32]) {
		result.ArrayIdentityFingerprint = fingerprint("phantowd-md-array-v1\n", superblock[16:32])
	}
	if !allZero(superblock[168:184]) {
		result.MemberIdentityFingerprint = fingerprint("phantowd-md-member-v1\n", superblock[168:184])
	}
	result.Status = StatusCandidate
	return result, nil
}

func newObservation(partition Partition) Observation {
	last := uint64(0)
	if partition.SizeLBA != 0 && partition.StartLBA <= math.MaxUint64-(partition.SizeLBA-1) {
		last = partition.StartLBA + partition.SizeLBA - 1
	}
	return Observation{Status: StatusUnsupported, PartitionNumber: partition.Number,
		PartitionFirstLBA: partition.StartLBA, PartitionLastLBA: last,
		SuperblockChecksumStatus: "not-validated"}
}

func damaged(result Observation) Observation {
	result.Status = StatusDamaged
	return result
}

func unsupported(result Observation) Observation {
	result.Status = StatusUnsupported
	return result
}

func readAt(source io.ReaderAt, buffer []byte, offset uint64, size int64) error {
	if size < 0 || offset > uint64(size) || offset > math.MaxInt64 || uint64(len(buffer)) > uint64(size)-offset {
		return ErrUnsafeSource
	}
	n, err := source.ReadAt(buffer, int64(offset))
	if err != nil || n != len(buffer) {
		return errors.New("MD metadata read failed")
	}
	return nil
}

func mdV1Checksum(superblock []byte) uint32 {
	copyForChecksum := append([]byte(nil), superblock...)
	clear(copyForChecksum[mdV1ChecksumOffset : mdV1ChecksumOffset+4])
	var sum uint64
	for offset := 0; offset+4 <= len(copyForChecksum); offset += 4 {
		sum += uint64(binary.LittleEndian.Uint32(copyForChecksum[offset : offset+4]))
	}
	if len(copyForChecksum)%4 == 2 {
		sum += uint64(binary.LittleEndian.Uint16(copyForChecksum[len(copyForChecksum)-2:]))
	}
	return uint32(sum) + uint32(sum>>32)
}

func fingerprint(domain string, identity []byte) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, domain)
	_, _ = hash.Write(identity)
	return hex.EncodeToString(hash.Sum(nil))
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

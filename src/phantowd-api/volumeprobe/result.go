// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package volumeprobe supervises the read-only metadata helper. Its results
// are internal observations, never permissions to mount, format or activate.
package volumeprobe

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

var (
	ErrUnsafe   = errors.New("unsafe volume probe input")
	ErrBusy     = errors.New("volume probe already active")
	ErrProbe    = errors.New("volume probe failed")
	ErrResponse = errors.New("invalid volume probe response")
)

const (
	maxOutput           = 64 * 1024
	maxDiagnostic       = 1024
	maxPartitionEntries = 256
)

// Partition is private on-disk metadata. It is not serialized to public HTTP
// and is not, by itself, evidence of supported layout or mount authorization.
type Partition struct {
	Number    uint32
	Start512B uint64
	Size512B  uint64
	UUID      string
	TypeID    string
	Extended  bool
}

// PartitionTable is returned only when both table metadata and every supported
// entry passed strict validation. Unsupported/ambiguous tables return no table.
type PartitionTable struct {
	Scheme     string
	ID         string
	Partitions []Partition
}

// Result contains private storage identity. Do not log or expose it through
// public diagnostics. Unidentified is not empty, healthy or safe to provision.
type Result struct {
	Status         string
	SourceKind     string
	Filesystem     string
	FilesystemUUID string
	PartitionTable *PartitionTable
}

type partitionResponse struct {
	Number    *uint32 `json:"number"`
	Start512B *uint64 `json:"start_512b_sectors"`
	Size512B  *uint64 `json:"size_512b_sectors"`
	UUID      *string `json:"uuid"`
	TypeID    *string `json:"type_id"`
	Extended  *bool   `json:"extended"`
}

type response struct {
	SchemaVersion          int                  `json:"schema_version"`
	Status                 *string              `json:"status"`
	SourceKind             *string              `json:"source_kind"`
	Filesystem             *string              `json:"filesystem"`
	FilesystemUUID         *string              `json:"filesystem_uuid"`
	PartitionTable         *string              `json:"partition_table"`
	PartitionTableID       *string              `json:"partition_table_id"`
	Partitions             *[]partitionResponse `json:"partitions"`
	MountPerformed         *bool                `json:"mount_performed"`
	CompatibilityQualified *bool                `json:"compatibility_qualified"`
	ActivationAllowed      *bool                `json:"activation_allowed"`
}

func decode(input io.Reader) (Result, error) {
	var wire response
	fields := map[string]bool{"schema_version": true, "status": true, "source_kind": true,
		"filesystem": true, "filesystem_uuid": true, "partition_table": true,
		"partition_table_id": true, "partitions": true, "mount_performed": true,
		"compatibility_qualified": true, "activation_allowed": true,
		"number": true, "start_512b_sectors": true, "size_512b_sectors": true,
		"uuid": true, "type_id": true, "extended": true}
	if configjson.Decode(input, &wire, maxOutput, 3, fields) != nil || wire.SchemaVersion != 2 ||
		wire.Status == nil || wire.SourceKind == nil || wire.Filesystem == nil || wire.FilesystemUUID == nil ||
		wire.PartitionTable == nil || wire.PartitionTableID == nil || wire.Partitions == nil || *wire.Partitions == nil ||
		wire.MountPerformed == nil || wire.CompatibilityQualified == nil || wire.ActivationAllowed == nil ||
		*wire.MountPerformed || *wire.CompatibilityQualified || *wire.ActivationAllowed {
		return Result{}, ErrResponse
	}
	result := Result{Status: *wire.Status, SourceKind: *wire.SourceKind,
		Filesystem: *wire.Filesystem, FilesystemUUID: *wire.FilesystemUUID}
	if result.SourceKind != "regular-image" && result.SourceKind != "block-device" {
		return Result{}, ErrResponse
	}
	switch result.Status {
	case "ext-metadata":
		if (result.Filesystem != "ext2" && result.Filesystem != "ext3" && result.Filesystem != "ext4") ||
			!validUUID(result.FilesystemUUID) || *wire.PartitionTable != "" || *wire.PartitionTableID != "" || len(*wire.Partitions) != 0 {
			return Result{}, ErrResponse
		}
	case "other-signature":
		if result.Filesystem != "" || result.FilesystemUUID != "" {
			return Result{}, ErrResponse
		}
	case "unusable-signature", "unidentified", "ambiguous":
		if result.Filesystem != "" || result.FilesystemUUID != "" ||
			*wire.PartitionTable != "" || *wire.PartitionTableID != "" || len(*wire.Partitions) != 0 {
			return Result{}, ErrResponse
		}
	default:
		return Result{}, ErrResponse
	}

	if *wire.PartitionTable == "" {
		if *wire.PartitionTableID != "" || len(*wire.Partitions) != 0 {
			return Result{}, ErrResponse
		}
		return result, nil
	}
	if result.Status != "other-signature" {
		return Result{}, ErrResponse
	}
	table := &PartitionTable{Scheme: *wire.PartitionTable, ID: *wire.PartitionTableID,
		Partitions: make([]Partition, 0, len(*wire.Partitions))}
	if len(*wire.Partitions) > maxPartitionEntries {
		return Result{}, ErrResponse
	}
	switch table.Scheme {
	case "gpt":
		if !validUUID(table.ID) {
			return Result{}, ErrResponse
		}
	case "dos":
		if !validDOSID(table.ID) {
			return Result{}, ErrResponse
		}
	default:
		return Result{}, ErrResponse
	}

	seenNumbers := make(map[uint32]bool, len(*wire.Partitions))
	seenUUIDs := make(map[string]bool, len(*wire.Partitions))
	extendedCount := 0
	for _, part := range *wire.Partitions {
		if part.Number == nil || part.Start512B == nil || part.Size512B == nil ||
			part.UUID == nil || part.TypeID == nil || part.Extended == nil ||
			*part.Number == 0 || *part.Start512B == 0 || *part.Size512B == 0 ||
			*part.Start512B > ^uint64(0)-*part.Size512B ||
			seenNumbers[*part.Number] || seenUUIDs[*part.UUID] {
			return Result{}, ErrResponse
		}
		seenNumbers[*part.Number] = true
		seenUUIDs[*part.UUID] = true
		if table.Scheme == "gpt" {
			if *part.Number > 4096 || *part.Extended || !validUUID(*part.UUID) || !validUUID(*part.TypeID) {
				return Result{}, ErrResponse
			}
		} else {
			if *part.Number > 256 || !validDOSPartitionID(table.ID, *part.Number, *part.UUID) || !validDOSType(*part.TypeID) {
				return Result{}, ErrResponse
			}
			extendedType := *part.TypeID == "0x05" || *part.TypeID == "0x0f" || *part.TypeID == "0x85"
			if *part.Extended != extendedType || (*part.Extended && *part.Number > 4) {
				return Result{}, ErrResponse
			}
			if *part.Extended {
				extendedCount++
				if extendedCount > 1 {
					return Result{}, ErrResponse
				}
			}
		}
		table.Partitions = append(table.Partitions, Partition{Number: *part.Number,
			Start512B: *part.Start512B, Size512B: *part.Size512B, UUID: *part.UUID,
			TypeID: *part.TypeID, Extended: *part.Extended})
	}
	for i := range table.Partitions {
		for j := 0; j < i; j++ {
			left, right := table.Partitions[i], table.Partitions[j]
			if left.Extended || right.Extended {
				continue
			}
			if rangesOverlap(left.Start512B, left.Start512B+left.Size512B,
				right.Start512B, right.Start512B+right.Size512B) {
				return Result{}, ErrResponse
			}
		}
	}
	if table.Scheme == "dos" && extendedCount == 0 {
		for _, part := range table.Partitions {
			if part.Number > 4 {
				return Result{}, ErrResponse
			}
		}
	}
	if table.Scheme == "dos" && extendedCount == 1 {
		var container *Partition
		for i := range table.Partitions {
			if table.Partitions[i].Extended {
				container = &table.Partitions[i]
				break
			}
		}
		if container == nil {
			return Result{}, ErrResponse
		}
		containerEnd := container.Start512B + container.Size512B
		for _, part := range table.Partitions {
			if part.Extended {
				continue
			}
			if part.Number < 5 {
				if rangesOverlap(part.Start512B, part.Start512B+part.Size512B,
					container.Start512B, containerEnd) {
					return Result{}, ErrResponse
				}
			} else if part.Start512B < container.Start512B || part.Start512B+part.Size512B > containerEnd {
				return Result{}, ErrResponse
			}
		}
	}
	result.PartitionTable = table
	return result, nil
}

func rangesOverlap(aStart, aEnd, bStart, bEnd uint64) bool {
	return aStart < bEnd && bStart < aEnd
}

func validDOSID(value string) bool {
	if len(value) != 8 || !lowerHex(value) {
		return false
	}
	return value != "00000000"
}

func validDOSPartitionID(tableID string, number uint32, value string) bool {
	suffix := strconv.FormatUint(uint64(number), 16)
	if len(suffix) < 2 {
		suffix = "0" + suffix
	}
	return value == tableID+"-"+suffix
}

func validDOSType(value string) bool {
	return len(value) == 4 && strings.HasPrefix(value, "0x") && lowerHex(value[2:]) && value != "0x00"
}

func lowerHex(value string) bool {
	for _, ch := range value {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	nonzero := false
	for i, ch := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
		nonzero = nonzero || ch != '0'
	}
	return nonzero
}

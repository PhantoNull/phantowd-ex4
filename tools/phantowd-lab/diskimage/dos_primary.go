// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const StatusDOSPrimary Status = "observed-dos-primary"

type DOSPrimaryReport struct {
	Format              string                `json:"format"`
	SchemaVersion       int                   `json:"schema_version"`
	Status              Status                `json:"status"`
	WDCompatibility     string                `json:"wd_compatibility"`
	LogicalSectorBytes  int                   `json:"logical_sector_bytes"`
	DiskSectors         uint64                `json:"disk_sectors"`
	PartitionCount      int                   `json:"partition_count"`
	RawIdentityRedacted bool                  `json:"raw_identity_redacted"`
	ImageMetadataRead   bool                  `json:"image_metadata_read"`
	BlockDeviceOpened   bool                  `json:"block_device_opened"`
	MutationsPerformed  bool                  `json:"mutations_performed"`
	AssemblyPerformed   bool                  `json:"assembly_performed"`
	MountPerformed      bool                  `json:"mount_performed"`
	Partitions          []DOSPrimaryPartition `json:"partitions"`
	Findings            []string              `json:"findings"`
	Limitations         []string              `json:"limitations"`
}

type DOSPrimaryPartition struct {
	Number    int    `json:"number"`
	TypeCode  string `json:"type_code"`
	Bootable  bool   `json:"bootable"`
	FirstLBA  uint64 `json:"first_lba"`
	LastLBA   uint64 `json:"last_lba"`
	SizeBytes uint64 `json:"size_bytes"`
}

// InspectDOSPrimary observes only the four primary entries using 512-byte LBAs.
// Boot code, disk signature, CHS fields, nested metadata and data are not interpreted.
// This is not a filesystem/WD-layout recognizer or storage admission.
func InspectDOSPrimary(image io.ReaderAt, size int64) (DOSPrimaryReport, error) {
	report := DOSPrimaryReport{Format: "phantowd-dos-primary-inspection", SchemaVersion: 1,
		Status: StatusDamaged, WDCompatibility: "unqualified", LogicalSectorBytes: logicalSectorBytes,
		RawIdentityRedacted: true, Partitions: []DOSPrimaryPartition{}, Findings: []string{},
		Limitations: []string{"primary-entry geometry only; 512-byte logical sectors must be independently known", "no boot, filesystem, array, WD layout, health or migration qualification; no identities or data are returned"}}
	if image == nil || size < 0 {
		return report, errors.New("invalid DOS image reader or size")
	}
	if size < logicalSectorBytes || size%logicalSectorBytes != 0 {
		report.Findings = []string{"image size is not a whole 512-byte sector count"}
		return report, nil
	}
	header := make([]byte, logicalSectorBytes)
	if err := readAt(image, header, 0, size); err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	report.DiskSectors = uint64(size / logicalSectorBytes)
	if header[510] != 0x55 || header[511] != 0xaa {
		report.Status = StatusUnsupported
		report.Findings = []string{"DOS signature is absent"}
		return report, nil
	}
	partitions := []DOSPrimaryPartition{}
	for slot := 0; slot < 4; slot++ {
		entry := header[446+slot*16 : 462+slot*16]
		if bytes.Equal(entry, make([]byte, 16)) {
			continue
		}
		switch entry[4] {
		case 0x05, 0x0f, 0x85, 0xee, 0x51, 0x53, 0x54, 0x55:
			report.Status = StatusUnsupported
			report.Findings = []string{"extended, protective/hybrid or translated-overlay tables require a different inspector"}
			return report, nil
		}
		first, count := uint64(binary.LittleEndian.Uint32(entry[8:])), uint64(binary.LittleEndian.Uint32(entry[12:]))
		if entry[4] == 0 || entry[0] != 0 && entry[0] != 0x80 || first == 0 || count == 0 || first+count > report.DiskSectors {
			report.Findings = []string{"primary entry has invalid flags, type or extent"}
			return report, nil
		}
		for _, previous := range partitions {
			if first <= previous.LastLBA && first+count-1 >= previous.FirstLBA {
				report.Findings = []string{"primary partition extents overlap"}
				return report, nil
			}
		}
		partitions = append(partitions, DOSPrimaryPartition{
			Number: slot + 1, TypeCode: fmt.Sprintf("%02x", entry[4]),
			Bootable: entry[0] == 0x80, FirstLBA: first,
			LastLBA: first + count - 1, SizeBytes: count * logicalSectorBytes,
		})
	}
	report.Status, report.Partitions, report.PartitionCount = StatusDOSPrimary, partitions, len(partitions)
	return report, nil
}

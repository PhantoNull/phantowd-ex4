// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
)

func TestInspectValidGPTImageRedactsIdentitiesAndNeverAuthorizesWDLayout(t *testing.T) {
	image := syntheticGPTImage()
	report, err := Inspect(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusValid || report.PartitionCount != 1 || len(report.Partitions) != 1 ||
		report.WDCompatibility != "unqualified" || report.BlockDeviceOpened || report.MutationsPerformed ||
		report.AssemblyPerformed || report.MountPerformed || !report.RawIdentityRedacted {
		t.Fatalf("unexpected GPT inspection: %+v", report)
	}
	partition := report.Partitions[0]
	if partition.Number != 1 || partition.FirstLBA != 40 || partition.LastLBA != 49 ||
		partition.SizeBytes != 10*logicalSectorBytes || partition.TypeGUID != linuxFilesystemTypeGUID {
		t.Fatalf("incorrect partition preview: %+v", partition)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"fixture-disk-guid", "fixture-partition-guid", "deadbeef", "/dev/sda"} {
		if strings.Contains(string(encoded), identity) {
			t.Fatalf("report leaked source identity %q: %s", identity, encoded)
		}
	}
}

func TestInspectRejectsMalformedOrNonstandardGPTWithoutRepair(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		status Status
	}{
		{
			name: "primary header crc",
			mutate: func(image []byte) {
				image[logicalSectorBytes+16] ^= 0xff
			},
			status: StatusDamaged,
		},
		{
			name: "backup header crc",
			mutate: func(image []byte) {
				image[len(image)-logicalSectorBytes+20] ^= 0xff
			},
			status: StatusDamaged,
		},
		{
			name: "primary partition array crc",
			mutate: func(image []byte) {
				image[2*logicalSectorBytes+40] ^= 0xff
				refreshHeaderCRC(image, 1)
				refreshHeaderCRC(image, uint64(len(image)/logicalSectorBytes-1))
			},
			status: StatusDamaged,
		},
		{
			name: "nonzero primary reserved field",
			mutate: func(image []byte) {
				image[logicalSectorBytes+20] = 1
				refreshHeaderCRC(image, 1)
			},
			status: StatusDamaged,
		},
		{
			name: "primary and backup arrays disagree",
			mutate: func(image []byte) {
				backupArrayOffset := (len(image)/logicalSectorBytes - 1 - 32) * logicalSectorBytes
				backupEntries := image[backupArrayOffset : backupArrayOffset+gptEntryBytes*4]
				backupEntries[48] = 1
				backupEntriesCRC := crc32.ChecksumIEEE(backupEntries)
				backupHeaderOffset := len(image) - logicalSectorBytes
				binary.LittleEndian.PutUint32(image[backupHeaderOffset+88:backupHeaderOffset+92], backupEntriesCRC)
				refreshHeaderCRC(image, uint64(len(image)/logicalSectorBytes-1))
			},
			status: StatusDamaged,
		},
		{
			name: "overlapping partitions",
			mutate: func(image []byte) {
				entries := image[2*logicalSectorBytes : 2*logicalSectorBytes+gptEntryBytes]
				putGPTEntry(entries[gptEntryBytes:], 48, 52, 2)
				refreshArraysAndHeaders(image)
			},
			status: StatusDamaged,
		},
		{
			name: "duplicate partition unique GUID",
			mutate: func(image []byte) {
				entries := image[2*logicalSectorBytes : 2*logicalSectorBytes+gptEntryBytes*4]
				second := entries[gptEntryBytes : 2*gptEntryBytes]
				putGPTEntry(second, 50, 52, 2)
				copy(second[16:32], entries[16:32])
				refreshArraysAndHeaders(image)
			},
			status: StatusDamaged,
		},
		{
			name: "hybrid MBR",
			mutate: func(image []byte) {
				image[446+16+4] = 0x83
			},
			status: StatusUnsupported,
		},
		{
			name: "truncated backup GPT",
			mutate: func(image []byte) {
				image[len(image)-logicalSectorBytes+24] = 0
			},
			status: StatusDamaged,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticGPTImage()
			test.mutate(image)
			report, err := Inspect(bytes.NewReader(image), int64(len(image)))
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != test.status || report.MutationsPerformed || report.AssemblyPerformed || report.MountPerformed {
				t.Fatalf("status=%q want %q: %+v", report.Status, test.status, report)
			}
		})
	}
}

func TestInspectClassifiesUnsupportedInputsAndBoundsGPT(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		size int64
		want Status
	}{
		{name: "non GPT file", data: make([]byte, 4096), size: 4096, want: StatusUnsupported},
		{name: "non sector aligned", data: syntheticGPTImage(), size: int64(len(syntheticGPTImage()) - 1), want: StatusDamaged},
		{name: "too short", data: make([]byte, logicalSectorBytes), size: logicalSectorBytes, want: StatusUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Inspect(bytes.NewReader(test.data), test.size)
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != test.want {
				t.Fatalf("status=%q want %q: %+v", report.Status, test.want, report)
			}
		})
	}
	if _, err := Inspect(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative image size accepted")
	}
}

const gptEntryBytes = 128

func syntheticGPTImage() []byte {
	const sectors = 128
	image := make([]byte, sectors*logicalSectorBytes)
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0xee
	binary.LittleEndian.PutUint32(image[446+8:], 1)
	binary.LittleEndian.PutUint32(image[446+12:], sectors-1)

	primaryEntries := image[2*logicalSectorBytes : 2*logicalSectorBytes+gptEntryBytes*4]
	putGPTEntry(primaryEntries, 40, 49, 1)
	backupEntriesLBA := uint64(sectors - 1 - 32)
	backupEntriesOffset := int(backupEntriesLBA * logicalSectorBytes)
	backupEntries := image[backupEntriesOffset : backupEntriesOffset+gptEntryBytes*4]
	copy(backupEntries, primaryEntries)
	entriesCRC := crc32.ChecksumIEEE(primaryEntries)
	putGPTHeader(image[logicalSectorBytes:2*logicalSectorBytes], 1, sectors-1, 2, entriesCRC)
	putGPTHeader(image[(sectors-1)*logicalSectorBytes:], sectors-1, 1, backupEntriesLBA, entriesCRC)
	return image
}

func putGPTEntry(entry []byte, firstLBA, lastLBA uint64, uniqueSuffix byte) {
	copy(entry[:16], mustGUIDBytes(linuxFilesystemTypeGUID))
	unique := mustGUIDBytes("11111111-2222-4333-8444-555555555555")
	unique[15] = uniqueSuffix
	copy(entry[16:32], unique)
	binary.LittleEndian.PutUint64(entry[32:40], firstLBA)
	binary.LittleEndian.PutUint64(entry[40:48], lastLBA)
}

func putGPTHeader(header []byte, currentLBA, backupLBA, entriesLBA uint64, entriesCRC uint32) {
	copy(header[:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], currentLBA)
	binary.LittleEndian.PutUint64(header[32:40], backupLBA)
	binary.LittleEndian.PutUint64(header[40:48], 34)
	binary.LittleEndian.PutUint64(header[48:56], 94)
	diskGUID := mustGUIDBytes("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	copy(header[56:72], diskGUID)
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], 4)
	binary.LittleEndian.PutUint32(header[84:88], gptEntryBytes)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	refreshHeaderCRCBytes(header)
}

func refreshArraysAndHeaders(image []byte) {
	entries := image[2*logicalSectorBytes : 2*logicalSectorBytes+gptEntryBytes*4]
	backupEntriesLBA := uint64(len(image)/logicalSectorBytes - 1 - 32)
	backupOffset := int(backupEntriesLBA * logicalSectorBytes)
	copy(image[backupOffset:backupOffset+len(entries)], entries)
	entriesCRC := crc32.ChecksumIEEE(entries)
	binary.LittleEndian.PutUint32(image[logicalSectorBytes+88:logicalSectorBytes+92], entriesCRC)
	binary.LittleEndian.PutUint32(image[len(image)-logicalSectorBytes+88:len(image)-logicalSectorBytes+92], entriesCRC)
	refreshHeaderCRC(image, 1)
	refreshHeaderCRC(image, uint64(len(image)/logicalSectorBytes-1))
}

func refreshHeaderCRC(image []byte, lba uint64) {
	header := image[int(lba*logicalSectorBytes):int((lba+1)*logicalSectorBytes)]
	refreshHeaderCRCBytes(header)
}

func refreshHeaderCRCBytes(header []byte) {
	size := int(binary.LittleEndian.Uint32(header[12:16]))
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:size]))
}

func mustGUIDBytes(value string) []byte {
	var guid [16]byte
	for offset, source := 0, 0; source < len(value); {
		if value[source] == '-' {
			source++
			continue
		}
		high, highOK := hexNibble(value[source])
		low, lowOK := hexNibble(value[source+1])
		if !highOK || !lowOK {
			panic("bad synthetic GPT GUID")
		}
		guid[offset] = high<<4 | low
		offset++
		source += 2
	}
	guid[0], guid[1], guid[2], guid[3] = guid[3], guid[2], guid[1], guid[0]
	guid[4], guid[5] = guid[5], guid[4]
	guid[6], guid[7] = guid[7], guid[6]
	return guid[:]
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

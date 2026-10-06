// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package diskimage validates generic GPT structure in caller-supplied raw
// image files. It does not identify or authorize any WD storage layout.
package diskimage

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
)

const (
	logicalSectorBytes = 512
	minimumHeaderBytes = 92
	maximumHeaderBytes = logicalSectorBytes
	minimumEntryBytes  = 128
	maximumEntryBytes  = 1024
	maximumEntries     = 128
	maximumArrayBytes  = 128 * 1024
)

type Status string

const (
	StatusValid       Status = "valid-gpt"
	StatusDamaged     Status = "damaged"
	StatusUnsupported Status = "unsupported"
)

const linuxFilesystemTypeGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"

type Report struct {
	Format                  string      `json:"format"`
	SchemaVersion           int         `json:"schema_version"`
	Status                  Status      `json:"status"`
	WDCompatibility         string      `json:"wd_compatibility"`
	LogicalSectorBytes      int         `json:"logical_sector_bytes"`
	DiskSectors             uint64      `json:"disk_sectors"`
	PartitionCount          int         `json:"partition_count"`
	PrimaryHeaderValid      bool        `json:"primary_header_valid"`
	BackupHeaderValid       bool        `json:"backup_header_valid"`
	PartitionArraysEqual    bool        `json:"partition_arrays_equal"`
	DiskIdentityFingerprint string      `json:"disk_identity_fingerprint,omitempty"`
	TableFingerprint        string      `json:"table_fingerprint,omitempty"`
	RawIdentityRedacted     bool        `json:"raw_identity_redacted"`
	ImageMetadataRead       bool        `json:"image_metadata_read"`
	BlockDeviceOpened       bool        `json:"block_device_opened"`
	MutationsPerformed      bool        `json:"mutations_performed"`
	AssemblyPerformed       bool        `json:"assembly_performed"`
	MountPerformed          bool        `json:"mount_performed"`
	Partitions              []Partition `json:"partitions"`
	Findings                []string    `json:"findings"`
	Limitations             []string    `json:"limitations"`
}

type Partition struct {
	Number              int    `json:"number"`
	TypeGUID            string `json:"type_guid"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	FirstLBA            uint64 `json:"first_lba"`
	LastLBA             uint64 `json:"last_lba"`
	SizeBytes           uint64 `json:"size_bytes"`
	Attributes          uint64 `json:"attributes"`
}

type gptHeader struct {
	revision       uint32
	headerSize     uint32
	currentLBA     uint64
	backupLBA      uint64
	firstUsableLBA uint64
	lastUsableLBA  uint64
	diskGUID       [16]byte
	entriesLBA     uint64
	entryCount     uint32
	entrySize      uint32
	entriesCRC     uint32
	entries        []byte
}

type partitionRange struct {
	first uint64
	last  uint64
}

// Inspect checks the protective MBR and both GPT copies in a regular-file raw
// image. Only bounded partition-table metadata is read through ReaderAt.
func Inspect(image io.ReaderAt, size int64) (Report, error) {
	report := newReport()
	if image == nil || size < 0 {
		return report, errors.New("invalid disk-image reader or size")
	}
	if size < 34*logicalSectorBytes {
		report.Status = StatusUnsupported
		report.Findings = []string{"input is too small to contain a standard GPT layout"}
		return report, nil
	}
	if size%logicalSectorBytes != 0 {
		report.Status = StatusDamaged
		report.Findings = []string{"image size is not aligned to the supported 512-byte logical sector size"}
		return report, nil
	}

	sectors := uint64(size / logicalSectorBytes)
	report.DiskSectors = sectors
	protective, err := validateProtectiveMBR(image, size, sectors)
	if err != nil {
		return report, err
	}
	report.ImageMetadataRead = true
	if protective == protectiveMBRUnsupported {
		report.Status = StatusUnsupported
		report.Findings = []string{"input is not a protective-MBR GPT image or uses a hybrid MBR"}
		return report, nil
	}
	if protective == protectiveMBRInvalid {
		report.Status = StatusDamaged
		report.Findings = []string{"protective MBR is malformed or inconsistent with image size"}
		return report, nil
	}

	primary, err := readGPTHeader(image, size, sectors, 1, true)
	if err != nil {
		return report, err
	}
	if primary == nil {
		report.Status = StatusDamaged
		report.Findings = []string{"primary GPT header or partition array is invalid"}
		return report, nil
	}
	backup, err := readGPTHeader(image, size, sectors, sectors-1, false)
	if err != nil {
		return report, err
	}
	if backup == nil || !headersAgree(primary, backup, sectors) {
		report.PrimaryHeaderValid = true
		report.Status = StatusDamaged
		report.Findings = []string{"primary and backup GPT metadata are missing, invalid, or inconsistent"}
		return report, nil
	}
	report.PrimaryHeaderValid = true
	report.BackupHeaderValid = true
	report.PartitionArraysEqual = true

	partitions, findings := parsePartitions(primary)
	if len(findings) != 0 {
		report.Status = StatusDamaged
		report.Findings = findings
		return report, nil
	}
	report.Status = StatusValid
	report.PartitionCount = len(partitions)
	report.Partitions = partitions
	report.DiskIdentityFingerprint = fingerprint("phantowd-gpt-disk-v1\n", primary.diskGUID[:])
	report.TableFingerprint = tableFingerprint(primary)
	report.Findings = []string{"GPT structures are internally consistent; WD storage compatibility remains unqualified"}
	return report, nil
}

func newReport() Report {
	return Report{
		Format:              "phantowd-disk-image-inspection",
		SchemaVersion:       1,
		Status:              StatusUnsupported,
		WDCompatibility:     "unqualified",
		LogicalSectorBytes:  logicalSectorBytes,
		RawIdentityRedacted: true,
		ImageMetadataRead:   false,
		BlockDeviceOpened:   false,
		MutationsPerformed:  false,
		AssemblyPerformed:   false,
		MountPerformed:      false,
		Partitions:          []Partition{},
		Findings:            []string{},
		Limitations: []string{
			"only GPT partition-table metadata in a supplied raw image is inspected; filesystem, RAID, health and WD XML data are not read",
			"a structurally valid GPT is not proof of a supported WD layout or healthy user data",
			"disk and partition unique GUIDs are replaced with deterministic SHA-256 fingerprints; fingerprints are not authenticity checks",
			"input must be a regular local file; no block device is opened, and no array is assembled or filesystem mounted",
		},
	}
}

type protectiveMBRStatus uint8

const (
	protectiveMBRInvalid protectiveMBRStatus = iota
	protectiveMBRValid
	protectiveMBRUnsupported
)

func validateProtectiveMBR(image io.ReaderAt, size int64, sectors uint64) (protectiveMBRStatus, error) {
	mbr := make([]byte, logicalSectorBytes)
	if err := readAt(image, mbr, 0, size); err != nil {
		return protectiveMBRInvalid, err
	}
	if mbr[510] != 0x55 || mbr[511] != 0xaa {
		return protectiveMBRUnsupported, nil
	}
	protectiveCount := 0
	for index := 0; index < 4; index++ {
		entry := mbr[446+index*16 : 446+(index+1)*16]
		typeID := entry[4]
		start := binary.LittleEndian.Uint32(entry[8:12])
		count := binary.LittleEndian.Uint32(entry[12:16])
		if typeID == 0 && start == 0 && count == 0 {
			continue
		}
		if typeID != 0xee {
			return protectiveMBRUnsupported, nil
		}
		protectiveCount++
		wantCount := uint64(sectors - 1)
		if wantCount > math.MaxUint32 {
			wantCount = math.MaxUint32
		}
		if start != 1 || uint64(count) != wantCount || entry[0] != 0 && entry[0] != 0x80 {
			return protectiveMBRInvalid, nil
		}
	}
	if protectiveCount != 1 {
		return protectiveMBRUnsupported, nil
	}
	return protectiveMBRValid, nil
}

func readGPTHeader(image io.ReaderAt, size int64, sectors, lba uint64, primary bool) (*gptHeader, error) {
	if lba >= sectors {
		return nil, nil
	}
	buffer := make([]byte, logicalSectorBytes)
	if err := readAt(image, buffer, lba*logicalSectorBytes, size); err != nil {
		return nil, err
	}
	if string(buffer[:8]) != "EFI PART" {
		return nil, nil
	}
	headerSize := binary.LittleEndian.Uint32(buffer[12:16])
	if headerSize < minimumHeaderBytes || headerSize > maximumHeaderBytes {
		return nil, nil
	}
	headerBytes := append([]byte(nil), buffer[:headerSize]...)
	wantHeaderCRC := binary.LittleEndian.Uint32(headerBytes[16:20])
	for index := 16; index < 20; index++ {
		headerBytes[index] = 0
	}
	if crc32.ChecksumIEEE(headerBytes) != wantHeaderCRC {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(buffer[20:24]) != 0 {
		return nil, nil
	}
	header := &gptHeader{
		revision:       binary.LittleEndian.Uint32(buffer[8:12]),
		headerSize:     headerSize,
		currentLBA:     binary.LittleEndian.Uint64(buffer[24:32]),
		backupLBA:      binary.LittleEndian.Uint64(buffer[32:40]),
		firstUsableLBA: binary.LittleEndian.Uint64(buffer[40:48]),
		lastUsableLBA:  binary.LittleEndian.Uint64(buffer[48:56]),
		entriesLBA:     binary.LittleEndian.Uint64(buffer[72:80]),
		entryCount:     binary.LittleEndian.Uint32(buffer[80:84]),
		entrySize:      binary.LittleEndian.Uint32(buffer[84:88]),
		entriesCRC:     binary.LittleEndian.Uint32(buffer[88:92]),
	}
	copy(header.diskGUID[:], buffer[56:72])
	if !validHeaderGeometry(header, sectors, lba, primary) {
		return nil, nil
	}
	arrayBytes := uint64(header.entryCount) * uint64(header.entrySize)
	if arrayBytes > maximumArrayBytes || arrayBytes > uint64(math.MaxInt) {
		return nil, nil
	}
	header.entries = make([]byte, int(arrayBytes))
	if err := readAt(image, header.entries, header.entriesLBA*logicalSectorBytes, size); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(header.entries) != header.entriesCRC {
		return nil, nil
	}
	return header, nil
}

func validHeaderGeometry(header *gptHeader, sectors, lba uint64, primary bool) bool {
	if header.revision != 0x00010000 || header.currentLBA != lba || header.backupLBA >= sectors ||
		header.firstUsableLBA < 2 || header.firstUsableLBA > header.lastUsableLBA ||
		header.lastUsableLBA >= sectors || allZero(header.diskGUID[:]) ||
		header.entryCount == 0 || header.entryCount > maximumEntries ||
		header.entrySize < minimumEntryBytes || header.entrySize > maximumEntryBytes || header.entrySize%8 != 0 {
		return false
	}
	arrayBytes := uint64(header.entryCount) * uint64(header.entrySize)
	arraySectors := (arrayBytes + logicalSectorBytes - 1) / logicalSectorBytes
	if arraySectors == 0 || header.entriesLBA >= sectors || arraySectors > sectors-header.entriesLBA {
		return false
	}
	arrayLastLBA := header.entriesLBA + arraySectors - 1
	if primary {
		return lba == 1 && header.backupLBA == sectors-1 && header.entriesLBA >= 2 && arrayLastLBA < header.firstUsableLBA
	}
	return lba == sectors-1 && header.backupLBA == 1 && arrayLastLBA < lba && header.entriesLBA > header.lastUsableLBA
}

func headersAgree(primary, backup *gptHeader, sectors uint64) bool {
	return primary.currentLBA == 1 && primary.backupLBA == sectors-1 &&
		backup.currentLBA == sectors-1 && backup.backupLBA == 1 &&
		primary.revision == backup.revision && primary.headerSize == backup.headerSize &&
		primary.firstUsableLBA == backup.firstUsableLBA && primary.lastUsableLBA == backup.lastUsableLBA &&
		primary.diskGUID == backup.diskGUID && primary.entryCount == backup.entryCount &&
		primary.entrySize == backup.entrySize && primary.entriesCRC == backup.entriesCRC &&
		bytesEqual(primary.entries, backup.entries)
}

func parsePartitions(header *gptHeader) ([]Partition, []string) {
	partitions := make([]Partition, 0, header.entryCount)
	ranges := make([]partitionRange, 0, header.entryCount)
	uniqueGUIDs := make(map[[16]byte]bool)
	for index := uint32(0); index < header.entryCount; index++ {
		start := uint64(index) * uint64(header.entrySize)
		entry := header.entries[start : start+uint64(header.entrySize)]
		var typeGUID, uniqueGUID [16]byte
		copy(typeGUID[:], entry[:16])
		if allZero(typeGUID[:]) {
			continue
		}
		copy(uniqueGUID[:], entry[16:32])
		firstLBA := binary.LittleEndian.Uint64(entry[32:40])
		lastLBA := binary.LittleEndian.Uint64(entry[40:48])
		if allZero(uniqueGUID[:]) || uniqueGUIDs[uniqueGUID] || firstLBA < header.firstUsableLBA ||
			firstLBA > lastLBA || lastLBA > header.lastUsableLBA {
			return partitions, []string{"GPT contains an empty/duplicate partition identity or invalid partition bounds"}
		}
		uniqueGUIDs[uniqueGUID] = true
		sectors := lastLBA - firstLBA + 1
		if sectors > math.MaxUint64/logicalSectorBytes {
			return partitions, []string{"GPT partition byte size overflows the supported range"}
		}
		partitions = append(partitions, Partition{
			Number:              int(index + 1),
			TypeGUID:            formatGUID(typeGUID),
			IdentityFingerprint: fingerprint("phantowd-gpt-partition-v1\n", uniqueGUID[:]),
			FirstLBA:            firstLBA,
			LastLBA:             lastLBA,
			SizeBytes:           sectors * logicalSectorBytes,
			Attributes:          binary.LittleEndian.Uint64(entry[48:56]),
		})
		ranges = append(ranges, partitionRange{first: firstLBA, last: lastLBA})
	}
	sort.Slice(partitions, func(i, j int) bool { return partitions[i].FirstLBA < partitions[j].FirstLBA })
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	for index := 1; index < len(ranges); index++ {
		if ranges[index].first <= ranges[index-1].last {
			return partitions, []string{"GPT partitions overlap"}
		}
	}
	return partitions, nil
}

func tableFingerprint(header *gptHeader) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "phantowd-gpt-table-v1\n")
	_, _ = hash.Write(header.diskGUID[:])
	_, _ = hash.Write(header.entries)
	return hex.EncodeToString(hash.Sum(nil))
}

func fingerprint(domain string, identity []byte) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, domain)
	_, _ = hash.Write(identity)
	return hex.EncodeToString(hash.Sum(nil))
}

func formatGUID(guid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		guid[8], guid[9], guid[10:16])
}

func readAt(reader io.ReaderAt, buffer []byte, offset uint64, size int64) error {
	if size < 0 || offset > uint64(size) || offset > math.MaxInt64 ||
		uint64(len(buffer)) > uint64(size)-offset {
		return errors.New("disk-image metadata read is out of bounds")
	}
	read, err := reader.ReadAt(buffer, int64(offset))
	if err != nil || read != len(buffer) {
		return errors.New("cannot read disk-image metadata")
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

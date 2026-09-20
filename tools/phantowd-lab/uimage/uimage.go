// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package uimage implements bounded, read-only inspection of the legacy
// U-Boot image format. It never constructs an image or accesses a device.
package uimage

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
)

const (
	HeaderSize = int64(64)
	Magic      = uint32(0x27051956)
)

// Report describes one legacy U-Boot image and its independently calculated
// header and payload checksums.
type Report struct {
	Format              string   `json:"format"`
	Size                int64    `json:"size"`
	HeaderSize          int64    `json:"header_size"`
	Magic               string   `json:"magic"`
	MagicValid          bool     `json:"magic_valid"`
	TimestampUnix       uint32   `json:"timestamp_unix"`
	TimestampUTC        string   `json:"timestamp_utc"`
	DataSize            int64    `json:"data_size"`
	TrailingBytes       int64    `json:"trailing_bytes"`
	LoadAddress         string   `json:"load_address"`
	EntryPoint          string   `json:"entry_point"`
	ExpectedHeaderCRC32 string   `json:"expected_header_crc32"`
	ActualHeaderCRC32   string   `json:"actual_header_crc32"`
	HeaderCRC32Valid    bool     `json:"header_crc32_valid"`
	ExpectedDataCRC32   string   `json:"expected_data_crc32"`
	ActualDataCRC32     string   `json:"actual_data_crc32"`
	DataCRC32Valid      bool     `json:"data_crc32_valid"`
	OS                  Identity `json:"os"`
	Architecture        Identity `json:"architecture"`
	ImageType           Identity `json:"image_type"`
	Compression         Identity `json:"compression"`
	Name                string   `json:"name"`
	Valid               bool     `json:"valid"`
	Problems            []string `json:"problems,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// Identity preserves the numeric legacy identifier even when its label is
// unknown to this deliberately small inspector.
type Identity struct {
	ID   byte   `json:"id"`
	Name string `json:"name"`
}

// Inspect validates a regular-file legacy U-Boot image through ReaderAt. The
// caller is responsible for rejecting device, pipe, and symlink inputs.
func Inspect(r io.ReaderAt, size int64) (Report, error) {
	report := Report{
		Format:     "u-boot-legacy-image",
		Size:       size,
		HeaderSize: HeaderSize,
	}
	if size < HeaderSize {
		return report, fmt.Errorf("file is smaller than the %d-byte legacy U-Boot header", HeaderSize)
	}

	header := make([]byte, HeaderSize)
	if err := readAtFull(r, header, 0); err != nil {
		return report, fmt.Errorf("read legacy U-Boot header: %w", err)
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	expectedHeaderCRC := binary.BigEndian.Uint32(header[4:8])
	timestamp := binary.BigEndian.Uint32(header[8:12])
	dataSize := int64(binary.BigEndian.Uint32(header[12:16]))
	loadAddress := binary.BigEndian.Uint32(header[16:20])
	entryPoint := binary.BigEndian.Uint32(header[20:24])
	expectedDataCRC := binary.BigEndian.Uint32(header[24:28])

	report.Magic = hex32(magic)
	report.MagicValid = magic == Magic
	report.TimestampUnix = timestamp
	report.TimestampUTC = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
	report.DataSize = dataSize
	report.LoadAddress = hex32(loadAddress)
	report.EntryPoint = hex32(entryPoint)
	report.ExpectedHeaderCRC32 = hex32(expectedHeaderCRC)
	report.ExpectedDataCRC32 = hex32(expectedDataCRC)
	report.OS = identity(header[28], osNames)
	report.Architecture = identity(header[29], architectureNames)
	report.ImageType = identity(header[30], imageTypeNames)
	report.Compression = identity(header[31], compressionNames)
	report.Name = cString(header[32:64])

	headerForCRC := append([]byte(nil), header...)
	clear(headerForCRC[4:8])
	actualHeaderCRC := crc32.ChecksumIEEE(headerForCRC)
	report.ActualHeaderCRC32 = hex32(actualHeaderCRC)
	report.HeaderCRC32Valid = actualHeaderCRC == expectedHeaderCRC

	if !report.MagicValid {
		report.Problems = append(report.Problems, fmt.Sprintf("legacy U-Boot magic is %s, want %s", report.Magic, hex32(Magic)))
	}
	if !report.HeaderCRC32Valid {
		report.Problems = append(report.Problems, fmt.Sprintf("header CRC32 is %s, want %s", report.ActualHeaderCRC32, report.ExpectedHeaderCRC32))
	}
	if dataSize == 0 {
		report.Problems = append(report.Problems, "declared payload size is zero")
	}
	if dataSize > size-HeaderSize {
		return report, fmt.Errorf("declared payload is %d bytes, file contains %d bytes after the header", dataSize, size-HeaderSize)
	}
	report.TrailingBytes = size - HeaderSize - dataSize
	if report.TrailingBytes != 0 {
		noun := "bytes"
		if report.TrailingBytes == 1 {
			noun = "byte"
		}
		report.Warnings = append(report.Warnings, fmt.Sprintf("file has %d %s after the declared payload; legacy U-Boot does not authenticate this trailing data", report.TrailingBytes, noun))
	}

	dataCRC := crc32.NewIEEE()
	if _, err := io.Copy(dataCRC, io.NewSectionReader(r, HeaderSize, dataSize)); err != nil {
		return report, fmt.Errorf("checksum payload: %w", err)
	}
	actualDataCRC := dataCRC.Sum32()
	report.ActualDataCRC32 = hex32(actualDataCRC)
	report.DataCRC32Valid = actualDataCRC == expectedDataCRC
	if !report.DataCRC32Valid {
		report.Problems = append(report.Problems, fmt.Sprintf("payload CRC32 is %s, want %s", report.ActualDataCRC32, report.ExpectedDataCRC32))
	}

	report.Valid = len(report.Problems) == 0
	return report, nil
}

func identity(id byte, names map[byte]string) Identity {
	name, ok := names[id]
	if !ok {
		name = "unknown"
	}
	return Identity{ID: id, Name: name}
}

func hex32(value uint32) string {
	return fmt.Sprintf("0x%08x", value)
}

func cString(data []byte) string {
	if index := strings.IndexByte(string(data), 0); index >= 0 {
		data = data[:index]
	}
	return strings.TrimSpace(string(data))
}

func readAtFull(r io.ReaderAt, data []byte, offset int64) error {
	n, err := r.ReadAt(data, offset)
	if n == len(data) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

var osNames = map[byte]string{
	0: "invalid",
	5: "linux",
}

var architectureNames = map[byte]string{
	0: "invalid",
	2: "arm",
}

var imageTypeNames = map[byte]string{
	0:  "invalid",
	1:  "standalone",
	2:  "kernel",
	3:  "ramdisk",
	4:  "multi",
	5:  "firmware",
	6:  "script",
	7:  "filesystem",
	8:  "flatdt",
	14: "kernel-no-load",
}

var compressionNames = map[byte]string{
	0: "none",
	1: "gzip",
	2: "bzip2",
	3: "lzma",
	4: "lzo",
	5: "lz4",
	6: "zstd",
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package vendorupdate implements read-only inspection of the legacy WD My
// Cloud EX4 update container and its packed logical mtd3 component. It does not
// construct, extract, install, or write firmware.
package vendorupdate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	OuterHeaderSize    = int64(128)
	ExtensionSize      = int64(96)
	LogicalHeaderSize  = int64(2048)
	ControllerHeadSize = int64(128)
	RescueHeaderSize   = int64(2048)
)

var outerMagic = []byte{0x55, 0xaa, 'L', 'i', 'g', 'h', 't', 'n', 'i', 0x00, 0x55, 0xaa}
var controllerMagic = []byte{0x55, 0xaa, 'L', 'i', 'g', 'u', 'P', 0x00, 0x00, 0x00, 0x55, 0xaa}
var rescueMagic = []byte{0x55, 0xaa, 'L', 'i', 'g', 'R', 'e', 's', 'c', 'u', 'r', 'e'}

// ModelSelector is the five-byte legacy compatibility selector. Its meaning
// was recovered from the vendor's GPL merge utility.
type ModelSelector struct {
	Product  byte `json:"product"`
	Custom   byte `json:"custom"`
	Model    byte `json:"model"`
	Hardware byte `json:"hardware"`
	Sub      byte `json:"sub"`
}

// Component describes one outer-container component.
type Component struct {
	Name        string `json:"name"`
	Offset      int64  `json:"offset"`
	Length      int64  `json:"length"`
	ExpectedXOR uint32 `json:"expected_xor"`
	ActualXOR   uint32 `json:"actual_xor"`
	XORValid    bool   `json:"xor_valid"`
}

// LogicalImage describes the packed logical mtd3 object. It is not a physical
// NAND dump and contains no OOB/ECC representation.
type LogicalImage struct {
	Size               int64    `json:"size"`
	HeaderSize         int64    `json:"header_size"`
	PayloadLength      int64    `json:"payload_length"`
	ExpectedPayloadXOR uint32   `json:"expected_payload_xor"`
	ActualPayloadXOR   uint32   `json:"actual_payload_xor"`
	XORValid           bool     `json:"xor_valid"`
	SquashFSMagic      bool     `json:"squashfs_magic"`
	Valid              bool     `json:"valid"`
	Problems           []string `json:"problems,omitempty"`
}

// RescueImage describes the logical rescue object reconstructed by the vendor
// reader. The schema is established by static analysis of rescue_fw; it is not
// yet corroborated by an exact-device mtd4 dump. Per-device MAC strings are
// deliberately never returned.
type RescueImage struct {
	Format                string        `json:"format"`
	SchemaEvidence        string        `json:"schema_evidence"`
	Size                  int64         `json:"size"`
	HeaderSize            int64         `json:"header_size"`
	PayloadLength         int64         `json:"payload_length"`
	TrailingBytes         int64         `json:"trailing_bytes"`
	ExpectedPayloadXOR    uint32        `json:"expected_payload_xor"`
	ActualPayloadXOR      uint32        `json:"actual_payload_xor"`
	XORValid              bool          `json:"xor_valid"`
	MagicValid            bool          `json:"magic_valid"`
	Version               string        `json:"version,omitempty"`
	BoardModelID          byte          `json:"board_model_id"`
	Selector              ModelSelector `json:"selector"`
	IdentityFieldsPresent bool          `json:"identity_fields_present"`
	IdentityFieldsValid   bool          `json:"identity_fields_valid"`
	IdentityRedacted      bool          `json:"identity_redacted"`
	Valid                 bool          `json:"valid"`
	Problems              []string      `json:"problems,omitempty"`
}

// ControllerImage describes the independently wrapped front-controller image.
type ControllerImage struct {
	HeaderSize         int64    `json:"header_size"`
	PayloadLength      int64    `json:"payload_length"`
	ExpectedPayloadXOR uint32   `json:"expected_payload_xor"`
	ActualPayloadXOR   uint32   `json:"actual_payload_xor"`
	XORValid           bool     `json:"xor_valid"`
	MagicValid         bool     `json:"magic_valid"`
	Valid              bool     `json:"valid"`
	Problems           []string `json:"problems,omitempty"`
}

// Extension describes the single legacy extension descriptor observed in the
// final EX4 update. Execute is reported but never acted on.
type Extension struct {
	DescriptorOffset int64            `json:"descriptor_offset"`
	Path             string           `json:"path"`
	Name             string           `json:"name"`
	ModeDecimal      uint32           `json:"mode_decimal"`
	Execute          uint32           `json:"execute"`
	Content          Component        `json:"content"`
	Controller       *ControllerImage `json:"controller,omitempty"`
}

// Report is a complete read-only inspection result.
type Report struct {
	Format         string        `json:"format"`
	Size           int64         `json:"size"`
	Release        string        `json:"release"`
	Selector       ModelSelector `json:"selector"`
	HeaderXOR      uint32        `json:"header_xor"`
	HeaderXORValid bool          `json:"header_xor_valid"`
	Components     []Component   `json:"components"`
	LogicalImage   *LogicalImage `json:"logical_image,omitempty"`
	Extension      *Extension    `json:"extension,omitempty"`
	Valid          bool          `json:"valid"`
	Problems       []string      `json:"problems,omitempty"`
}

// Inspect reads metadata and computes integrity fields without modifying or
// extracting the input. ReaderAt avoids trusting attacker-controlled lengths
// for allocations.
func Inspect(r io.ReaderAt, size int64) (Report, error) {
	report := Report{Format: "wd-mycloud-ex4-legacy-update", Size: size}
	if size < OuterHeaderSize {
		return report, fmt.Errorf("file is smaller than the %d-byte outer header", OuterHeaderSize)
	}

	header := make([]byte, OuterHeaderSize)
	if err := readAtFull(r, header, 0); err != nil {
		return report, fmt.Errorf("read outer header: %w", err)
	}
	if !bytes.Equal(header[0x30:0x3c], outerMagic) {
		report.Problems = append(report.Problems, "legacy Lightni product magic does not match")
	}

	report.Release = cString(header[0x41:0x78])
	report.Selector = ModelSelector{
		Product: header[0x3c], Custom: header[0x3d], Model: header[0x3e],
		Hardware: header[0x3f], Sub: header[0x40],
	}
	report.HeaderXOR = xorBytes(header)
	report.HeaderXORValid = report.HeaderXOR == 0
	if !report.HeaderXORValid {
		report.Problems = append(report.Problems, fmt.Sprintf("outer header XOR is %#08x, want zero", report.HeaderXOR))
	}

	componentSpecs := []struct {
		name                  string
		offsetField, lenField int
		xorField              int
	}{
		{"kernel", 0x00, 0x04, 0x20},
		{"ramdisk", 0x08, 0x0c, 0x24},
		{"logical-mtd3", 0x10, 0x14, 0x28},
		{"factory-defaults", 0x18, 0x1c, 0x2c},
	}

	for _, spec := range componentSpecs {
		component := Component{
			Name:        spec.name,
			Offset:      int64(le32(header[spec.offsetField:])),
			Length:      int64(le32(header[spec.lenField:])),
			ExpectedXOR: le32(header[spec.xorField:]),
		}
		if err := validateRange(component.Offset, component.Length, size); err != nil {
			return report, fmt.Errorf("%s component: %w", component.Name, err)
		}
		actual, err := xorRange(r, component.Offset, component.Length)
		if err != nil {
			return report, fmt.Errorf("checksum %s component: %w", component.Name, err)
		}
		component.ActualXOR = actual
		component.XORValid = actual == component.ExpectedXOR
		if !component.XORValid {
			report.Problems = append(report.Problems, fmt.Sprintf("%s XOR is %#08x, want %#08x", component.Name, actual, component.ExpectedXOR))
		}
		report.Components = append(report.Components, component)
	}

	if report.Components[0].Offset != OuterHeaderSize {
		report.Problems = append(report.Problems, "kernel does not begin immediately after the known 128-byte header")
	}
	for i := 1; i < len(report.Components); i++ {
		previous := report.Components[i-1]
		current := report.Components[i]
		if current.Offset < previous.Offset+previous.Length {
			return report, fmt.Errorf("%s overlaps %s", current.Name, previous.Name)
		}
	}

	logical := report.Components[2]
	logicalReport, err := InspectLogicalImage(io.NewSectionReader(r, logical.Offset, logical.Length), logical.Length)
	if err != nil {
		return report, fmt.Errorf("inspect logical mtd3 component: %w", err)
	}
	report.LogicalImage = &logicalReport
	for _, problem := range logicalReport.Problems {
		report.Problems = append(report.Problems, "logical mtd3: "+problem)
	}

	extensionOffset := int64(le32(header[0x7c:]))
	if extensionOffset != 0 {
		lastComponent := report.Components[len(report.Components)-1]
		if extensionOffset < lastComponent.Offset+lastComponent.Length {
			return report, errors.New("extension descriptor overlaps an outer component")
		}
		extension, extensionProblems, err := inspectExtension(r, size, extensionOffset)
		if err != nil {
			return report, err
		}
		report.Extension = extension
		report.Problems = append(report.Problems, extensionProblems...)
	}

	report.Valid = len(report.Problems) == 0
	return report, nil
}

// InspectLogicalImage validates the 2 KiB header plus packed SquashFS stream
// used as the logical mtd3 input. It deliberately makes no claim about the
// physical NAND OOB, ECC, or bad-block layout.
func InspectLogicalImage(r io.ReaderAt, size int64) (LogicalImage, error) {
	report := LogicalImage{Size: size, HeaderSize: LogicalHeaderSize}
	if size < LogicalHeaderSize {
		return report, fmt.Errorf("input is smaller than the %d-byte logical header", LogicalHeaderSize)
	}
	header := make([]byte, LogicalHeaderSize)
	if err := readAtFull(r, header, 0); err != nil {
		return report, fmt.Errorf("read logical header: %w", err)
	}
	report.PayloadLength = int64(le32(header[0:]))
	report.ExpectedPayloadXOR = le32(header[4:])
	if report.PayloadLength != size-LogicalHeaderSize {
		report.Problems = append(report.Problems, fmt.Sprintf("payload length is %d, file contains %d bytes after header", report.PayloadLength, size-LogicalHeaderSize))
	}
	if err := validateRange(LogicalHeaderSize, report.PayloadLength, size); err != nil {
		return report, fmt.Errorf("logical payload: %w", err)
	}
	actual, err := xorRange(r, LogicalHeaderSize, report.PayloadLength)
	if err != nil {
		return report, fmt.Errorf("checksum logical payload: %w", err)
	}
	report.ActualPayloadXOR = actual
	report.XORValid = actual == report.ExpectedPayloadXOR
	if !report.XORValid {
		report.Problems = append(report.Problems, fmt.Sprintf("payload XOR is %#08x, want %#08x", actual, report.ExpectedPayloadXOR))
	}
	magic := make([]byte, 4)
	if err := readAtFull(r, magic, LogicalHeaderSize); err != nil {
		return report, fmt.Errorf("read SquashFS magic: %w", err)
	}
	report.SquashFSMagic = bytes.Equal(magic, []byte("hsqs"))
	if !report.SquashFSMagic {
		report.Problems = append(report.Problems, "payload does not begin with little-endian SquashFS magic hsqs")
	}
	report.Valid = len(report.Problems) == 0
	return report, nil
}

// InspectRescueImage validates a regular-file copy of the packed logical
// rescue format. It never exposes the two per-device MAC fields present in the
// legacy header and makes no physical NAND/OOB/ECC claim.
func InspectRescueImage(r io.ReaderAt, size int64) (RescueImage, error) {
	report := RescueImage{
		Format:           "wd-mycloud-ex4-legacy-logical-rescue",
		SchemaEvidence:   "static-gpl-rescue_fw-needs-exact-device-corroboration",
		Size:             size,
		HeaderSize:       RescueHeaderSize,
		IdentityRedacted: true,
	}
	if size < RescueHeaderSize {
		return report, fmt.Errorf("input is smaller than the %d-byte rescue header", RescueHeaderSize)
	}
	header := make([]byte, RescueHeaderSize)
	if err := readAtFull(r, header, 0); err != nil {
		return report, fmt.Errorf("read rescue header: %w", err)
	}
	report.PayloadLength = int64(le32(header[0x14:]))
	report.ExpectedPayloadXOR = le32(header[0x18:])
	report.BoardModelID = header[0x30]
	report.MagicValid = bytes.Equal(header[0x32:0x3e], rescueMagic)
	report.Selector = ModelSelector{
		Product: header[0x3e], Custom: header[0x3f], Model: header[0x40],
		Hardware: header[0x41], Sub: header[0x42],
	}
	report.Version = cString(header[0x48:0x80])
	mac1, mac1Valid := parseLegacyMACField(header[0:20])
	mac2, mac2Valid := parseLegacyMACField(header[0x1c:0x30])
	report.IdentityFieldsPresent = hasNonZero(header[0:20]) && hasNonZero(header[0x1c:0x30])
	report.IdentityFieldsValid = mac1Valid && mac2Valid && mac1 != mac2
	if !report.IdentityFieldsValid {
		report.Problems = append(report.Problems, "rescue identity must contain two distinct, valid unicast MAC addresses")
	}
	if report.PayloadLength <= 0 {
		return report, errors.New("rescue payload length is zero")
	}
	if err := validateRange(RescueHeaderSize, report.PayloadLength, size); err != nil {
		return report, fmt.Errorf("rescue payload: %w", err)
	}
	report.TrailingBytes = size - RescueHeaderSize - report.PayloadLength
	actual, err := xorRange(r, RescueHeaderSize, report.PayloadLength)
	if err != nil {
		return report, fmt.Errorf("checksum rescue payload: %w", err)
	}
	report.ActualPayloadXOR = actual
	report.XORValid = actual == report.ExpectedPayloadXOR
	if !report.XORValid {
		report.Problems = append(report.Problems, fmt.Sprintf("payload XOR is %#08x, want %#08x", actual, report.ExpectedPayloadXOR))
	}
	if !report.MagicValid {
		report.Problems = append(report.Problems, "legacy LigRescure magic does not match")
	}
	if report.Selector.Product != 0 || report.Selector.Custom != 0x14 || report.Selector.Model != 0 {
		report.Problems = append(report.Problems, fmt.Sprintf(
			"rescue compatibility selector is product=%d custom=%d model=%d, want 0/20/0",
			report.Selector.Product, report.Selector.Custom, report.Selector.Model,
		))
	}
	report.Valid = len(report.Problems) == 0
	return report, nil
}

// parseLegacyMACField applies the tool's conservative interpretation of a
// 20-byte rescue identity field without retaining or exposing it in a report.
// The ASCII/padding encoding is inferred from static analysis and synthetic
// fixtures; it is not yet corroborated against an exact-device rescue record.
func parseLegacyMACField(field []byte) ([6]byte, bool) {
	var address [6]byte
	if len(field) != 20 {
		return address, false
	}
	for _, padding := range field[17:] {
		if padding != 0 {
			return address, false
		}
	}
	for octet := 0; octet < len(address); octet++ {
		start := octet * 3
		hi, hiOK := hexNibble(field[start])
		lo, loOK := hexNibble(field[start+1])
		if !hiOK || !loOK {
			return [6]byte{}, false
		}
		address[octet] = hi<<4 | lo
		if octet < len(address)-1 && field[start+2] != ':' {
			return [6]byte{}, false
		}
	}
	if address[0]&1 != 0 || address == [6]byte{} {
		return [6]byte{}, false
	}
	return address, true
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func inspectExtension(r io.ReaderAt, size, offset int64) (*Extension, []string, error) {
	if err := validateRange(offset, ExtensionSize, size); err != nil {
		return nil, nil, fmt.Errorf("extension descriptor: %w", err)
	}
	descriptor := make([]byte, ExtensionSize)
	if err := readAtFull(r, descriptor, offset); err != nil {
		return nil, nil, fmt.Errorf("read extension descriptor: %w", err)
	}
	extension := &Extension{
		DescriptorOffset: offset,
		Path:             cString(descriptor[0:32]),
		Name:             cString(descriptor[32:64]),
		ModeDecimal:      le32(descriptor[64:]),
		Execute:          le32(descriptor[68:]),
		Content: Component{
			Name:        "extension-content",
			Offset:      int64(le32(descriptor[80:])),
			Length:      int64(le32(descriptor[84:])),
			ExpectedXOR: le32(descriptor[88:]),
		},
	}
	if err := validateRange(extension.Content.Offset, extension.Content.Length, size); err != nil {
		return nil, nil, fmt.Errorf("extension content: %w", err)
	}
	if extension.Content.Offset < offset+ExtensionSize {
		return nil, nil, errors.New("extension content overlaps its descriptor")
	}
	actual, err := xorRange(r, extension.Content.Offset, extension.Content.Length)
	if err != nil {
		return nil, nil, fmt.Errorf("checksum extension content: %w", err)
	}
	extension.Content.ActualXOR = actual
	extension.Content.XORValid = actual == extension.Content.ExpectedXOR
	var problems []string
	if !extension.Content.XORValid {
		problems = append(problems, fmt.Sprintf("extension content XOR is %#08x, want %#08x", actual, extension.Content.ExpectedXOR))
	}
	if extension.Name == "uP.bin" {
		controller, err := inspectController(io.NewSectionReader(r, extension.Content.Offset, extension.Content.Length), extension.Content.Length)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect controller image: %w", err)
		}
		extension.Controller = &controller
		for _, problem := range controller.Problems {
			problems = append(problems, "controller image: "+problem)
		}
	}
	return extension, problems, nil
}

func inspectController(r io.ReaderAt, size int64) (ControllerImage, error) {
	report := ControllerImage{HeaderSize: ControllerHeadSize}
	if size < ControllerHeadSize {
		return report, fmt.Errorf("input is smaller than the %d-byte controller header", ControllerHeadSize)
	}
	header := make([]byte, ControllerHeadSize)
	if err := readAtFull(r, header, 0); err != nil {
		return report, err
	}
	declaredHeader := int64(le32(header[0:]))
	report.PayloadLength = int64(le32(header[4:]))
	report.ExpectedPayloadXOR = le32(header[0x20:])
	report.MagicValid = bytes.Equal(header[0x30:0x3c], controllerMagic)
	if declaredHeader != ControllerHeadSize {
		report.Problems = append(report.Problems, fmt.Sprintf("declared header size is %d, want %d", declaredHeader, ControllerHeadSize))
	}
	if !report.MagicValid {
		report.Problems = append(report.Problems, "legacy LiguP controller magic does not match")
	}
	if report.PayloadLength != size-ControllerHeadSize {
		report.Problems = append(report.Problems, fmt.Sprintf("payload length is %d, wrapper contains %d bytes after header", report.PayloadLength, size-ControllerHeadSize))
	}
	if err := validateRange(ControllerHeadSize, report.PayloadLength, size); err != nil {
		return report, fmt.Errorf("controller payload: %w", err)
	}
	actual, err := xorRange(r, ControllerHeadSize, report.PayloadLength)
	if err != nil {
		return report, err
	}
	report.ActualPayloadXOR = actual
	report.XORValid = actual == report.ExpectedPayloadXOR
	if !report.XORValid {
		report.Problems = append(report.Problems, fmt.Sprintf("payload XOR is %#08x, want %#08x", actual, report.ExpectedPayloadXOR))
	}
	report.Valid = len(report.Problems) == 0
	return report, nil
}

func validateRange(offset, length, size int64) error {
	if offset < 0 || length < 0 || offset > size || length > size-offset {
		return fmt.Errorf("range offset=%d length=%d exceeds file size %d", offset, length, size)
	}
	return nil
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

func xorRange(r io.ReaderAt, offset, length int64) (uint32, error) {
	if length == 0 {
		return 0, nil
	}
	reader := io.NewSectionReader(r, offset, length)
	buffer := make([]byte, 64*1024)
	word := make([]byte, 4)
	wordLength := 0
	var checksum uint32
	for {
		n, err := reader.Read(buffer)
		for _, value := range buffer[:n] {
			word[wordLength] = value
			wordLength++
			if wordLength == len(word) {
				checksum ^= binary.LittleEndian.Uint32(word)
				wordLength = 0
				clear(word)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if wordLength != 0 {
		checksum ^= binary.LittleEndian.Uint32(word)
	}
	return checksum, nil
}

func xorBytes(data []byte) uint32 {
	var checksum uint32
	for len(data) >= 4 {
		checksum ^= binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
	}
	if len(data) != 0 {
		var tail [4]byte
		copy(tail[:], data)
		checksum ^= binary.LittleEndian.Uint32(tail[:])
	}
	return checksum
}

func le32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data[:4])
}

func cString(data []byte) string {
	if index := bytes.IndexByte(data, 0); index >= 0 {
		data = data[:index]
	}
	return strings.TrimSpace(string(data))
}

func hasNonZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return true
		}
	}
	return false
}

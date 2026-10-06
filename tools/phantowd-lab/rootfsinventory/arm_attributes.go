// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"
)

const (
	maxARMAttributeBytes = 64 * 1024
	maxARMAttributeTags  = 128
	maxARMAttributeText  = 1024
)

// ARMAttribute records an explicitly encoded aeabi file-scope value, not an
// inferred default or a claim that machine instructions satisfy the declaration.
// TextHex preserves exact NTBS bytes (excluding NUL), including non-UTF-8 data.
// Tag 32 has both a numerical compatibility flag and a vendor string.
type ARMAttribute struct {
	Tag     uint64  `json:"tag"`
	Integer *uint64 `json:"integer,omitempty"`
	TextHex *string `json:"text_hex,omitempty"`
}

// ARMBuildAttributes is an offline observation with no execution authority.
// Only one aeabi file scope is supported; private vendor payloads are opaque.
// Invalid/unsupported observations contain no partial attribute roster.
type ARMBuildAttributes struct {
	Status                   string         `json:"status"`
	Reason                   string         `json:"reason,omitempty"`
	PrivateVendorSubsections int            `json:"private_vendor_subsections"`
	FileAttributes           []ARMAttribute `json:"file_attributes,omitempty"`
}

func inspectARMAttributes(file *elf.File) *ARMBuildAttributes {
	if file.Machine != elf.EM_ARM {
		return nil
	}
	var section *elf.Section
	for _, item := range file.Sections {
		if item.Name != ".ARM.attributes" && item.Type != elf.SectionType(0x70000003) {
			continue
		}
		if section != nil || item.Name != ".ARM.attributes" || item.Type != elf.SectionType(0x70000003) || item.Flags != 0 {
			return &ARMBuildAttributes{Status: "unsupported", Reason: "section-layout"}
		}
		section = item
	}
	if section == nil {
		return &ARMBuildAttributes{Status: "absent"}
	}
	if file.Class != elf.ELFCLASS32 {
		return &ARMBuildAttributes{Status: "unsupported", Reason: "elf-class"}
	}
	if section.Size == 0 || section.Size > maxARMAttributeBytes {
		return &ARMBuildAttributes{Status: "unsupported", Reason: "section-budget"}
	}
	// Never use Section.Data: compressed/malicious sections must not allocate
	// their claimed expanded size before our independent ceiling is applied.
	raw, err := io.ReadAll(io.LimitReader(section.Open(), maxARMAttributeBytes+1))
	if err != nil || len(raw) != int(section.Size) {
		return &ARMBuildAttributes{Status: "invalid", Reason: "section-read"}
	}
	return parseARMAttributes(raw, file.ByteOrder)
}

// The format follows Arm Addenda32 3.2; this deliberately bounded observer is
// not a linker, inheritance resolver, CPU classifier or conformance checker.
func parseARMAttributes(raw []byte, order binary.ByteOrder) *ARMBuildAttributes {
	fail := func(status, reason string) *ARMBuildAttributes {
		return &ARMBuildAttributes{Status: status, Reason: reason}
	}
	if len(raw) > maxARMAttributeBytes {
		return fail("unsupported", "section-budget")
	}
	if len(raw) == 0 || order == nil {
		return fail("invalid", "section-format")
	}
	if raw[0] != 'A' {
		return fail("unsupported", "section-version")
	}
	out := &ARMBuildAttributes{Status: "unobserved", Reason: "no-public-file-scope"}
	seenScope := false
	seen := map[uint64]ARMAttribute{}
	for offset, vendors := 1, 0; offset < len(raw); vendors++ {
		if vendors >= maxARMAttributeTags {
			return fail("unsupported", "vendor-budget")
		}
		if len(raw)-offset < 4 {
			return fail("invalid", "vendor-length")
		}
		length := uint64(order.Uint32(raw[offset:]))
		if length < 5 || length > uint64(len(raw)-offset) {
			return fail("invalid", "vendor-length")
		}
		vendor := raw[offset+4 : offset+int(length)]
		if bytes.IndexByte(vendor, 0) > maxARMAttributeText {
			return fail("unsupported", "text-budget")
		}
		name, data, ok := armAttributeText(vendor)
		if !ok || name == "" {
			return fail("invalid", "vendor-name")
		}
		offset += int(length)
		if name != "aeabi" {
			out.PrivateVendorSubsections++
			continue
		}
		if len(data) == 0 {
			return fail("invalid", "public-scope")
		}
		for len(data) != 0 {
			tag, rest, ok := armAttributeInteger(data)
			if !ok || len(rest) < 4 {
				return fail("invalid", "scope-length")
			}
			headerSize := len(data) - len(rest) + 4
			length := uint64(order.Uint32(rest))
			if length < uint64(headerSize) || length > uint64(len(data)) {
				return fail("invalid", "scope-length")
			}
			if tag != 1 || seenScope {
				return fail("unsupported", "public-scope-layout")
			}
			seenScope = true
			attributes := data[headerSize:int(length)]
			data = data[int(length):]
			for count := 0; len(attributes) != 0; count++ {
				if count >= maxARMAttributeTags {
					return fail("unsupported", "tag-budget")
				}
				tag, rest, ok := armAttributeInteger(attributes)
				if !ok {
					return fail("invalid", "attribute-tag")
				}
				item := ARMAttribute{Tag: tag}
				switch {
				case tag == 4 || tag == 5 || (tag > 32 && tag%2 == 1):
					if bytes.IndexByte(rest, 0) > maxARMAttributeText {
						return fail("unsupported", "text-budget")
					}
					text, remaining, valid := armAttributeText(rest)
					if !valid {
						return fail("invalid", "attribute-text")
					}
					encoded := hex.EncodeToString([]byte(text))
					item.TextHex, attributes = &encoded, remaining
				case tag >= 6 && tag <= 32 || tag > 32 && tag%2 == 0:
					value, remaining, valid := armAttributeInteger(rest)
					if !valid {
						return fail("invalid", "attribute-integer")
					}
					item.Integer, attributes = &value, remaining
					if tag == 32 {
						if bytes.IndexByte(attributes, 0) > maxARMAttributeText {
							return fail("unsupported", "text-budget")
						}
						text, remaining, valid := armAttributeText(attributes)
						if !valid {
							return fail("invalid", "compatibility-text")
						}
						encoded := hex.EncodeToString([]byte(text))
						item.TextHex, attributes = &encoded, remaining
					}
				default:
					return fail("unsupported", "attribute-encoding")
				}
				if previous, exists := seen[tag]; exists {
					if !sameARMAttribute(previous, item) {
						return fail("invalid", "conflicting-attribute")
					}
				} else {
					seen[tag] = item
				}
			}
		}
	}
	if seenScope {
		out.Status, out.Reason = "observed", ""
		for _, item := range seen {
			out.FileAttributes = append(out.FileAttributes, item)
		}
		sort.Slice(out.FileAttributes, func(i, j int) bool { return out.FileAttributes[i].Tag < out.FileAttributes[j].Tag })
	}
	return out
}

func armAttributeInteger(raw []byte) (uint64, []byte, bool) {
	value, length := binary.Uvarint(raw)
	if length <= 0 {
		return 0, nil, false
	}
	return value, raw[length:], true
}

func armAttributeText(raw []byte) (string, []byte, bool) {
	length := bytes.IndexByte(raw, 0)
	if length < 0 || length > maxARMAttributeText {
		return "", nil, false
	}
	return string(raw[:length]), raw[length+1:], true
}

func sameARMAttribute(a, b ARMAttribute) bool {
	return (a.Integer == nil && b.Integer == nil || a.Integer != nil && b.Integer != nil && *a.Integer == *b.Integer) &&
		(a.TextHex == nil && b.TextHex == nil || a.TextHex != nil && b.TextHex != nil && *a.TextHex == *b.TextHex)
}

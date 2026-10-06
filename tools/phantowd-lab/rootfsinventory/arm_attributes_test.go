// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
)

func attributeVendor(order binary.ByteOrder, name string, data []byte) []byte {
	raw := make([]byte, 4)
	raw = append(raw, []byte(name)...)
	raw = append(raw, 0)
	raw = append(raw, data...)
	order.PutUint32(raw, uint32(len(raw)))
	return raw
}

func attributeScope(order binary.ByteOrder, tag byte, data []byte) []byte {
	raw := append([]byte{tag, 0, 0, 0, 0}, data...)
	order.PutUint32(raw[1:], uint32(len(raw)))
	return raw
}

func attributeSection(order binary.ByteOrder, data []byte) []byte {
	return append([]byte{'A'}, attributeVendor(order, "aeabi", attributeScope(order, 1, data))...)
}

func attributesELF(order binary.ByteOrder, attributes []byte) []byte {
	// A regular synthetic ELF32 with null, shstrtab and ARM attributes sections.
	raw := minimalHeader(elf.ELFCLASS32, order, 0x05000200)
	raw = append(raw, make([]byte, 120)...)
	names := []byte("\x00.shstrtab\x00.ARM.attributes\x00")
	raw = append(raw, names...)
	offset := len(raw)
	raw = append(raw, attributes...)
	order.PutUint32(raw[32:], 64)
	order.PutUint16(raw[46:], 40)
	order.PutUint16(raw[48:], 3)
	order.PutUint16(raw[50:], 1)
	order.PutUint32(raw[104:], 1)
	order.PutUint32(raw[108:], uint32(elf.SHT_STRTAB))
	order.PutUint32(raw[120:], 184)
	order.PutUint32(raw[124:], uint32(len(names)))
	order.PutUint32(raw[144:], 11)
	order.PutUint32(raw[148:], 0x70000003)
	order.PutUint32(raw[160:], uint32(offset))
	order.PutUint32(raw[164:], uint32(len(attributes)))
	return raw
}

func TestARMAttributesExplicitZeroAndLosslessText(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := []byte{5, '5', 'T', 'E', 'J', 0, 6, 5, 8, 1, 9, 1, 10, 0, 32, 0, 'g', 'n', 'u', 0,
			65, 6, 11, 0, 67, 0xff, 0, 128, 1, 0}
		out := parseARMAttributes(attributeSection(order, data), order)
		if out.Status != "observed" || out.Reason != "" || len(out.FileAttributes) != 9 {
			t.Fatal(out)
		}
		byTag := map[uint64]ARMAttribute{}
		for _, item := range out.FileAttributes {
			byTag[item.Tag] = item
		}
		if *byTag[6].Integer != 5 || *byTag[10].Integer != 0 || *byTag[5].TextHex != "3554454a" ||
			*byTag[32].Integer != 0 || *byTag[32].TextHex != "676e75" || *byTag[65].TextHex != "060b" ||
			*byTag[67].TextHex != "ff" || *byTag[128].Integer != 0 {
			t.Fatal(out)
		}
		encoded, err := json.Marshal(out)
		if err != nil || !bytes.Contains(encoded, []byte(`"tag":10,"integer":0`)) ||
			!bytes.Contains(encoded, []byte(`"tag":67,"text_hex":"ff"`)) {
			t.Fatal(string(encoded), err)
		}
		info, err := inspectELF(bytes.NewReader(attributesELF(order, attributeSection(order, data))))
		if err != nil || info == nil || !reflect.DeepEqual(info.ARMAttributes, out) {
			t.Fatal(info, err)
		}
	}
}

func TestARMAttributesNoDefaultsAndOpaqueVendors(t *testing.T) {
	order := binary.LittleEndian
	for _, value := range []struct {
		data    []byte
		status  string
		private int
		tags    int
	}{
		{[]byte{'A'}, "unobserved", 0, 0},
		{append([]byte{'A'}, attributeVendor(order, "gnu", []byte{0xff, 0x81})...), "unobserved", 1, 0},
		{attributeSection(order, nil), "observed", 0, 0},
		{attributeSection(order, []byte{64, 1}), "observed", 0, 1},
		{attributeSection(order, []byte{6, 5, 6, 5}), "observed", 0, 1},
		{append(attributeSection(order, []byte{6, 5}), attributeVendor(order, "gnu", []byte{0xff})...), "observed", 1, 1},
	} {
		out := parseARMAttributes(value.data, order)
		if out.Status != value.status || out.PrivateVendorSubsections != value.private || len(out.FileAttributes) != value.tags {
			t.Fatal(out)
		}
	}
	info, err := inspectELF(bytes.NewReader(minimalHeader(elf.ELFCLASS32, order, 0x05000200)))
	if err != nil || info.ARMAttributes.Status != "absent" {
		t.Fatal(info, err)
	}
	raw := minimalHeader(elf.ELFCLASS64, order, 0)
	order.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	info, err = inspectELF(bytes.NewReader(raw))
	if err != nil || info.ARMAttributes != nil {
		t.Fatal(info, err)
	}
}

func TestARMAttributesRefuseIncompleteAmbiguousAndOverBudget(t *testing.T) {
	order := binary.LittleEndian
	malformed := [][]byte{nil, {'A', 1}, {'A', 0, 0, 0, 0},
		attributeSection(order, []byte{6}), attributeSection(order, []byte{6, 0x80}),
		attributeSection(order, []byte{5, 'x'}), attributeSection(order, []byte{32, 0}),
		attributeSection(order, []byte{6, 5, 6, 4}), attributeSection(order, []byte{5, 0, 5, 'x', 0}),
		attributeSection(order, append([]byte{6}, bytes.Repeat([]byte{0xff}, 11)...)),
		append(attributeSection(order, []byte{6, 5}), 0),
		append([]byte{'A'}, attributeVendor(order, "aeabi", nil)...),
		append([]byte{'A'}, attributeVendor(order, "", nil)...),
	}
	for _, raw := range malformed {
		out := parseARMAttributes(raw, order)
		if out.Status != "invalid" || len(out.FileAttributes) != 0 || out.PrivateVendorSubsections != 0 {
			t.Fatal("malformed input exposed partial observation", out)
		}
	}
	unsupported := [][]byte{
		{'B'},
		attributeSection(order, append([]byte{5}, append(bytes.Repeat([]byte{'x'}, maxARMAttributeText+1), 0)...)),
		attributeSection(order, append([]byte{32, 0}, append(bytes.Repeat([]byte{'x'}, maxARMAttributeText+1), 0)...)),
		append([]byte{'A'}, attributeVendor(order, string(bytes.Repeat([]byte{'x'}, maxARMAttributeText+1)), nil)...),
		attributeSection(order, []byte{3, 0}),
		append([]byte{'A'}, attributeVendor(order, "aeabi", attributeScope(order, 2, []byte{1, 0, 6, 5}))...),
		append(attributeSection(order, []byte{6, 5}), attributeVendor(order, "aeabi", attributeScope(order, 1, []byte{6, 5}))...),
		attributeSection(order, bytes.Repeat([]byte{6, 5}, maxARMAttributeTags+1)),
		append([]byte{'A'}, bytes.Repeat(attributeVendor(order, "gnu", nil), maxARMAttributeTags+1)...),
		bytes.Repeat([]byte{'A'}, maxARMAttributeBytes+1),
	}
	for _, raw := range unsupported {
		out := parseARMAttributes(raw, order)
		if out.Status != "unsupported" || len(out.FileAttributes) != 0 || out.PrivateVendorSubsections != 0 {
			t.Fatal("unsupported input exposed partial observation", out)
		}
	}
}

func TestARMAttributesSectionIdentityAndBudget(t *testing.T) {
	base := attributesELF(binary.LittleEndian, attributeSection(binary.LittleEndian, []byte{6, 5}))
	for _, mutate := range []func(*elf.File){
		func(f *elf.File) { f.Sections = append(f.Sections, f.Sections[2]) },
		func(f *elf.File) { f.Sections[2].Type = elf.SHT_PROGBITS },
		func(f *elf.File) { f.Sections[2].Name = ".unexpected" },
		func(f *elf.File) { f.Sections[2].Flags = elf.SHF_COMPRESSED },
		func(f *elf.File) { f.Class = elf.ELFCLASS64 },
		func(f *elf.File) { f.Sections[2].Size = maxARMAttributeBytes + 1 },
	} {
		file, err := elf.NewFile(bytes.NewReader(base))
		if err != nil {
			t.Fatal(err)
		}
		mutate(file)
		out := inspectARMAttributes(file)
		if out.Status != "unsupported" || len(out.FileAttributes) != 0 {
			t.Fatal(out)
		}
	}
	truncated := base[:len(base)-1]
	info, err := inspectELF(bytes.NewReader(truncated))
	if err != nil || info == nil || info.ARMAttributes.Status != "invalid" || len(info.ARMAttributes.FileAttributes) != 0 {
		t.Fatal("truncated attribute payload was silently accepted", info, err)
	}
}

func TestARMAttributesRejectLengthSpillAndMissingByteOrder(t *testing.T) {
	order := binary.LittleEndian
	base := attributeSection(order, []byte{6, 5})
	for _, offset := range []int{1, 12} {
		for _, length := range []uint32{0, 1, 4, 0xffffffff} {
			raw := bytes.Clone(base)
			order.PutUint32(raw[offset:], length)
			out := parseARMAttributes(raw, order)
			if out.Status != "invalid" || len(out.FileAttributes) != 0 {
				t.Fatal("length crossed its containing boundary", offset, length, out)
			}
		}
	}
	out := parseARMAttributes(base, nil)
	if out.Status != "invalid" || len(out.FileAttributes) != 0 {
		t.Fatal("invented byte order", out)
	}
}

func FuzzARMAttributesNeverExposePartialObservation(f *testing.F) {
	f.Add(attributeSection(binary.LittleEndian, []byte{5, '5', 0, 6, 5}), false)
	f.Add(attributeSection(binary.BigEndian, []byte{6, 5, 10, 0}), true)
	f.Add([]byte{'A'}, false)
	f.Fuzz(func(t *testing.T, raw []byte, big bool) {
		var order binary.ByteOrder = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		out := parseARMAttributes(raw, order)
		if out.Status != "observed" && (len(out.FileAttributes) != 0 || (out.Status != "unobserved" && out.PrivateVendorSubsections != 0)) {
			t.Fatal("failed parse exposed partial roster", out)
		}
		if len(out.FileAttributes) > maxARMAttributeTags {
			t.Fatal("unbounded observation", out)
		}
		if out.Status != "observed" && out.Status != "unobserved" && out.Status != "invalid" && out.Status != "unsupported" {
			t.Fatal("unknown observation state", out)
		}
		if (out.Status == "invalid" || out.Status == "unsupported") && out.Reason == "" {
			t.Fatal("refusal missing reason", out)
		}
		for index, item := range out.FileAttributes {
			if index > 0 && out.FileAttributes[index-1].Tag >= item.Tag {
				t.Fatal("unordered/duplicate tags", out)
			}
			if item.Integer == nil && item.TextHex == nil {
				t.Fatal("missing value", out)
			}
		}
	})
}

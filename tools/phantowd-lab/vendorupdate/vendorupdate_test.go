// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package vendorupdate

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestInspectSyntheticUpdate(t *testing.T) {
	fixture := syntheticUpdate(t)
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || !report.HeaderXORValid || report.Release != "2.13.synthetic" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Components) != 4 || report.LogicalImage == nil || !report.LogicalImage.Valid {
		t.Fatalf("missing valid logical image: %+v", report)
	}
	if report.Extension == nil || report.Extension.Controller == nil || !report.Extension.Controller.Valid {
		t.Fatalf("missing valid controller image: %+v", report.Extension)
	}
	if got := report.Selector; got != (ModelSelector{Product: 0, Custom: 0x14, Model: 0, Hardware: 1, Sub: 1}) {
		t.Fatalf("selector = %+v", got)
	}
}

func TestInspectDetectsCorruptComponent(t *testing.T) {
	fixture := syntheticUpdate(t)
	fixture[OuterHeaderSize] ^= 0xff
	report, err := Inspect(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.Components[0].XORValid {
		t.Fatalf("corruption was accepted: %+v", report)
	}
}

func TestInspectRejectsOutOfRangeComponent(t *testing.T) {
	fixture := syntheticUpdate(t)
	binary.LittleEndian.PutUint32(fixture[0x08:], uint32(len(fixture)-1))
	setHeaderXOR(fixture[:OuterHeaderSize])
	if _, err := Inspect(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
		t.Fatal("out-of-range component was accepted")
	}
}

func TestInspectRejectsOverlappingExtension(t *testing.T) {
	fixture := syntheticUpdate(t)
	binary.LittleEndian.PutUint32(fixture[0x7c:], binary.LittleEndian.Uint32(fixture[0x18:])+1)
	setHeaderXOR(fixture[:OuterHeaderSize])
	if _, err := Inspect(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
		t.Fatal("overlapping extension was accepted")
	}
}

func TestInspectLogicalImageRejectsWrongMagic(t *testing.T) {
	fixture := make([]byte, LogicalHeaderSize+4)
	binary.LittleEndian.PutUint32(fixture[0:], 4)
	copy(fixture[LogicalHeaderSize:], "nope")
	binary.LittleEndian.PutUint32(fixture[4:], xorBytes(fixture[LogicalHeaderSize:]))
	report, err := InspectLogicalImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.SquashFSMagic {
		t.Fatalf("wrong magic was accepted: %+v", report)
	}
}

func TestInspectSyntheticRescueRedactsIdentity(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	fixture := make([]byte, int(RescueHeaderSize)+len(payload)+4)
	copy(fixture[0:20], "02:11:22:33:44:55")
	copy(fixture[0x1c:0x30], "06:12:23:34:45:56")
	binary.LittleEndian.PutUint32(fixture[0x14:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixture[0x18:], xorBytes(payload))
	fixture[0x30] = 7
	copy(fixture[0x32:], rescueMagic)
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[0x48:], "1.00.synthetic")
	copy(fixture[RescueHeaderSize:], payload)
	report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || !report.IdentityFieldsPresent || !report.IdentityFieldsValid || !report.IdentityRedacted || report.TrailingBytes != 4 {
		t.Fatalf("unexpected rescue report: %+v", report)
	}
	if report.Version != "1.00.synthetic" || report.BoardModelID != 7 || report.Selector.Custom != 0x14 {
		t.Fatalf("unexpected rescue metadata: %+v", report)
	}
}

func TestInspectRescueRejectsIncompleteIdentityPair(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	fixture := make([]byte, int(RescueHeaderSize)+len(payload))
	copy(fixture[0:20], "02:11:22:33:44:55")
	binary.LittleEndian.PutUint32(fixture[0x14:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixture[0x18:], xorBytes(payload))
	copy(fixture[0x32:], rescueMagic)
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[RescueHeaderSize:], payload)

	report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid {
		t.Fatalf("rescue with only one identity address was accepted: %+v", report)
	}
}

func TestInspectRescueRejectsInvalidIdentityPairs(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
		mutate func([]byte)
	}{
		{name: "malformed address", first: "02:11:22:33:44:gg", second: "06:12:23:34:45:56"},
		{name: "multicast address", first: "01:11:22:33:44:55", second: "06:12:23:34:45:56"},
		{name: "zero address", first: "00:00:00:00:00:00", second: "06:12:23:34:45:56"},
		{name: "duplicate addresses", first: "02:11:22:33:44:55", second: "02:11:22:33:44:55"},
		{
			name:   "nonzero field padding",
			first:  "02:11:22:33:44:55",
			second: "06:12:23:34:45:56",
			mutate: func(fixture []byte) { fixture[17] = 'x' },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := syntheticRescue(tt.first, tt.second)
			if tt.mutate != nil {
				tt.mutate(fixture)
			}
			report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
			if err != nil {
				t.Fatal(err)
			}
			if report.Valid || report.IdentityFieldsValid || !report.IdentityRedacted {
				t.Fatalf("invalid identity pair was accepted or not marked redacted: %+v", report)
			}
			for _, problem := range report.Problems {
				if strings.Contains(problem, tt.first) || strings.Contains(problem, tt.second) {
					t.Fatalf("identity leaked through problem text: %q", problem)
				}
			}
		})
	}
}

func TestInspectRescueAcceptsHexLettersInLocalUnicastPair(t *testing.T) {
	fixture := syntheticRescue("02:ab:CD:3e:4F:50", "06:12:23:34:45:56")
	report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || !report.IdentityFieldsValid || !report.IdentityRedacted {
		t.Fatalf("valid case-insensitive unicast pair was rejected: %+v", report)
	}
}

func TestInspectRescueDetectsCorruptPayload(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	fixture := make([]byte, int(RescueHeaderSize)+len(payload))
	binary.LittleEndian.PutUint32(fixture[0x14:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixture[0x18:], xorBytes(payload))
	copy(fixture[0x32:], rescueMagic)
	copy(fixture[RescueHeaderSize:], payload)
	fixture[RescueHeaderSize] ^= 0xff
	report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.XORValid {
		t.Fatalf("corrupt rescue payload was accepted: %+v", report)
	}
}

func TestInspectRescueRejectsCompatibilityMismatch(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	fixture := make([]byte, int(RescueHeaderSize)+len(payload))
	binary.LittleEndian.PutUint32(fixture[0x14:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixture[0x18:], xorBytes(payload))
	copy(fixture[0x32:], rescueMagic)
	copy(fixture[0x3e:], []byte{1, 0x14, 0, 1, 1})
	copy(fixture[RescueHeaderSize:], payload)
	report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid {
		t.Fatalf("incompatible rescue selector was accepted: %+v", report)
	}
}

func syntheticRescue(first, second string) []byte {
	payload := []byte{1, 2, 3, 4}
	fixture := make([]byte, int(RescueHeaderSize)+len(payload))
	copy(fixture[0:20], first)
	copy(fixture[0x1c:0x30], second)
	binary.LittleEndian.PutUint32(fixture[0x14:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixture[0x18:], xorBytes(payload))
	copy(fixture[0x32:], rescueMagic)
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[0x48:], "1.00.synthetic")
	copy(fixture[RescueHeaderSize:], payload)
	return fixture
}

func FuzzInspect(f *testing.F) {
	fixture := syntheticUpdateForFuzz()
	f.Add(fixture)
	f.Add(syntheticRescue("02:11:22:33:44:55", "06:12:23:34:45:56"))
	f.Add([]byte("not firmware"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Inspect(bytes.NewReader(data), int64(len(data)))
		_, _ = InspectRescueImage(bytes.NewReader(data), int64(len(data)))
	})
}

func syntheticUpdate(t *testing.T) []byte {
	t.Helper()
	return syntheticUpdateForFuzz()
}

func syntheticUpdateForFuzz() []byte {
	align4 := func(value int) int { return (value + 3) &^ 3 }
	kernel := []byte{1, 2, 3, 4}
	ramdisk := []byte{5, 6, 7, 8}
	logicalPayload := []byte{'h', 's', 'q', 's', 9, 10, 11, 12}
	logical := make([]byte, int(LogicalHeaderSize)+len(logicalPayload))
	binary.LittleEndian.PutUint32(logical[0:], uint32(len(logicalPayload)))
	binary.LittleEndian.PutUint32(logical[4:], xorBytes(logicalPayload))
	copy(logical[LogicalHeaderSize:], logicalPayload)
	defaults := []byte{13, 14, 15, 16}
	controllerPayload := []byte{17, 18, 19, 20}
	controller := make([]byte, int(ControllerHeadSize)+len(controllerPayload))
	binary.LittleEndian.PutUint32(controller[0:], uint32(ControllerHeadSize))
	binary.LittleEndian.PutUint32(controller[4:], uint32(len(controllerPayload)))
	binary.LittleEndian.PutUint32(controller[0x20:], xorBytes(controllerPayload))
	copy(controller[0x30:], controllerMagic)
	copy(controller[ControllerHeadSize:], controllerPayload)

	kernelOffset := int(OuterHeaderSize)
	ramdiskOffset := align4(kernelOffset + len(kernel))
	logicalOffset := align4(ramdiskOffset + len(ramdisk))
	defaultsOffset := align4(logicalOffset + len(logical))
	extensionOffset := align4(defaultsOffset + len(defaults))
	controllerOffset := extensionOffset + int(ExtensionSize)
	fixture := make([]byte, controllerOffset+len(controller))
	copy(fixture[kernelOffset:], kernel)
	copy(fixture[ramdiskOffset:], ramdisk)
	copy(fixture[logicalOffset:], logical)
	copy(fixture[defaultsOffset:], defaults)
	copy(fixture[controllerOffset:], controller)

	header := fixture[:OuterHeaderSize]
	put := func(offset int, value int) { binary.LittleEndian.PutUint32(header[offset:], uint32(value)) }
	put(0x00, kernelOffset)
	put(0x04, len(kernel))
	put(0x08, ramdiskOffset)
	put(0x0c, len(ramdisk))
	put(0x10, logicalOffset)
	put(0x14, len(logical))
	put(0x18, defaultsOffset)
	put(0x1c, len(defaults))
	binary.LittleEndian.PutUint32(header[0x20:], xorBytes(kernel))
	binary.LittleEndian.PutUint32(header[0x24:], xorBytes(ramdisk))
	binary.LittleEndian.PutUint32(header[0x28:], xorBytes(logical))
	binary.LittleEndian.PutUint32(header[0x2c:], xorBytes(defaults))
	copy(header[0x30:], outerMagic)
	copy(header[0x3c:], []byte{0, 0x14, 0, 1, 1})
	copy(header[0x41:], "2.13.synthetic")
	put(0x7c, extensionOffset)

	descriptor := fixture[extensionOffset:controllerOffset]
	copy(descriptor[0:32], "/tmp")
	copy(descriptor[32:64], "uP.bin")
	binary.LittleEndian.PutUint32(descriptor[64:], 755)
	binary.LittleEndian.PutUint32(descriptor[68:], 0)
	binary.LittleEndian.PutUint32(descriptor[80:], uint32(controllerOffset))
	binary.LittleEndian.PutUint32(descriptor[84:], uint32(len(controller)))
	binary.LittleEndian.PutUint32(descriptor[88:], xorBytes(controller))
	setHeaderXOR(header)
	return fixture
}

func setHeaderXOR(header []byte) {
	binary.LittleEndian.PutUint32(header[0x78:], 0)
	binary.LittleEndian.PutUint32(header[0x78:], xorBytes(header))
}

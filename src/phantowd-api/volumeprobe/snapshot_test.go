// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestObservedBlockInventoryRefusesNamesOutsideOneKernelComponent(t *testing.T) {
	generation := BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 101}
	for _, name := range []string{"", ".", "..", "../sda", "sda/partition", "sda\\partition", "sda name"} {
		t.Run(name, func(t *testing.T) {
			if err := validateObservedBlockDevices([]ObservedBlockDevice{{Name: name, Generation: generation}}); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("unsafe kernel device name %q was accepted: %v", name, err)
			}
		})
	}
	if err := validateObservedBlockDevices([]ObservedBlockDevice{{Name: "sda", Generation: generation}}); err != nil {
		t.Fatalf("single kernel block name rejected: %v", err)
	}
}

func TestObservedBlockInventoryRequiresAnExactUniqueGenerationSet(t *testing.T) {
	generationA := BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 101}
	generationB := BlockDeviceGeneration{Major: 8, Minor: 32, DiskSequence: 102}
	for _, test := range []struct {
		name     string
		devices  []ObservedBlockDevice
		wantFail bool
	}{
		{name: "explicit empty", devices: []ObservedBlockDevice{}},
		{name: "nil is not an observation", devices: nil, wantFail: true},
		{name: "one observed device", devices: []ObservedBlockDevice{{Name: "sda", Generation: generationA}}},
		{name: "zero sequence", devices: []ObservedBlockDevice{{Name: "sda", Generation: BlockDeviceGeneration{Major: 8, Minor: 16}}}, wantFail: true},
		{name: "same generation repeated", devices: []ObservedBlockDevice{{Name: "sda", Generation: generationA}, {Name: "sdb", Generation: generationA}}, wantFail: true},
		{name: "one device number with conflicting generations", devices: []ObservedBlockDevice{{Name: "sda", Generation: generationA}, {Name: "sdb", Generation: BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 103}}}, wantFail: true},
		{name: "one sequence assigned to distinct devices", devices: []ObservedBlockDevice{{Name: "sda", Generation: generationA}, {Name: "sdb", Generation: BlockDeviceGeneration{Major: 8, Minor: 32, DiskSequence: 101}}}, wantFail: true},
		{name: "duplicate path name", devices: []ObservedBlockDevice{{Name: "sda", Generation: generationA}, {Name: "sda", Generation: generationB}}, wantFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateObservedBlockDevices(test.devices)
			if test.wantFail && !errors.Is(err, ErrUnsafe) {
				t.Fatalf("invalid observed inventory was accepted: %v", err)
			}
			if !test.wantFail && err != nil {
				t.Fatalf("valid observed inventory was refused: %v", err)
			}
		})
	}
	oversized := make([]ObservedBlockDevice, MaxSources+1)
	for index := range oversized {
		oversized[index] = ObservedBlockDevice{
			Name: fmt.Sprintf("sd%d", index),
			Generation: BlockDeviceGeneration{
				Major: 8, Minor: uint32(index + 1), DiskSequence: uint64(index + 1),
			},
		}
	}
	if err := validateObservedBlockDevices(oversized); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("oversized inventory was accepted: %v", err)
	}
}

func TestOrderCompleteBlockSourcesAgainstObservedInventory(t *testing.T) {
	newSource := func() *os.File {
		t.Helper()
		file, err := os.CreateTemp(t.TempDir(), "block-source")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return file
	}
	generationA := BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 101}
	generationB := BlockDeviceGeneration{Major: 8, Minor: 32, DiskSequence: 102}
	generationC := BlockDeviceGeneration{Major: 8, Minor: 48, DiskSequence: 103}
	fileA, fileB, fileC := newSource(), newSource(), newSource()
	for _, test := range []struct {
		name      string
		inventory []BlockDeviceGeneration
		sources   []BlockDeviceSource
		want      []*os.File
		wantError bool
	}{
		{
			name:      "reorders a complete set to inventory order",
			inventory: []BlockDeviceGeneration{generationA, generationB},
			sources:   []BlockDeviceSource{{File: fileB, Generation: generationB}, {File: fileA, Generation: generationA}},
			want:      []*os.File{fileA, fileB},
		},
		{
			name:      "rejects an omitted device",
			inventory: []BlockDeviceGeneration{generationA, generationB},
			sources:   []BlockDeviceSource{{File: fileA, Generation: generationA}},
			wantError: true,
		},
		{
			name:      "rejects an unobserved device",
			inventory: []BlockDeviceGeneration{generationA, generationB},
			sources:   []BlockDeviceSource{{File: fileA, Generation: generationA}, {File: fileC, Generation: generationC}},
			wantError: true,
		},
		{
			name:      "rejects an inventory alias",
			inventory: []BlockDeviceGeneration{generationA, generationA},
			sources:   []BlockDeviceSource{{File: fileA, Generation: generationA}, {File: fileC, Generation: generationA}},
			wantError: true,
		},
		{
			name:      "rejects one descriptor assigned to distinct devices",
			inventory: []BlockDeviceGeneration{generationA, generationB},
			sources:   []BlockDeviceSource{{File: fileA, Generation: generationA}, {File: fileA, Generation: generationB}},
			wantError: true,
		},
		{
			name:      "accepts an explicitly empty inventory",
			inventory: []BlockDeviceGeneration{},
			sources:   []BlockDeviceSource{},
			want:      []*os.File{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ordered, err := OrderCompleteBlockSources(test.inventory, test.sources)
			if test.wantError {
				if !errors.Is(err, ErrUnsafe) || ordered != nil {
					t.Fatalf("incomplete or conflicting set was accepted: %+v %v", ordered, err)
				}
				return
			}
			if err != nil || len(ordered) != len(test.want) {
				t.Fatalf("complete set failed: %+v %v", ordered, err)
			}
			for index, source := range ordered {
				if source.File != test.want[index] || source.Generation != test.inventory[index] {
					t.Fatalf("source %d not bound to inventory order: %+v", index, source)
				}
			}
		})
	}
	if _, err := OrderCompleteBlockSources(nil, []BlockDeviceSource{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("nil inventory must not stand in for an observed empty set: %v", err)
	}
	if _, err := OrderCompleteBlockSources([]BlockDeviceGeneration{}, nil); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("nil sources must not stand in for an explicitly empty descriptor set: %v", err)
	}
}

func TestOrderCompleteBlockSourcesRejectsOversizedInventory(t *testing.T) {
	inventory := make([]BlockDeviceGeneration, MaxSources+1)
	sources := make([]BlockDeviceSource, MaxSources+1)
	for index := range inventory {
		file, err := os.CreateTemp(t.TempDir(), "block-source")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		inventory[index] = BlockDeviceGeneration{
			Major:        8,
			Minor:        uint32(index),
			DiskSequence: uint64(index + 1),
		}
		sources[index] = BlockDeviceSource{File: file, Generation: inventory[index]}
	}
	ordered, err := OrderCompleteBlockSources(inventory, sources)
	if !errors.Is(err, ErrUnsafe) || ordered != nil {
		t.Fatalf("oversized inventory must be refused atomically: %d sources, %v", len(ordered), err)
	}
}

func TestValidGenerationSet(t *testing.T) {
	deviceA := BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 101}
	deviceB := BlockDeviceGeneration{Major: 8, Minor: 32, DiskSequence: 102}
	for _, test := range []struct {
		name        string
		generations []BlockDeviceGeneration
		valid       bool
	}{
		{"empty", []BlockDeviceGeneration{}, true},
		{"one device", []BlockDeviceGeneration{deviceA}, true},
		{"same descriptor alias", []BlockDeviceGeneration{deviceA, deviceA}, true},
		{"distinct devices", []BlockDeviceGeneration{deviceA, deviceB}, true},
		{"same device different generation", []BlockDeviceGeneration{deviceA, {Major: 8, Minor: 16, DiskSequence: 103}}, false},
		{"different devices same generation", []BlockDeviceGeneration{deviceA, {Major: 8, Minor: 32, DiskSequence: 101}}, false},
		{"zero device number", []BlockDeviceGeneration{{DiskSequence: 101}}, false},
		{"zero sequence", []BlockDeviceGeneration{{Major: 8, Minor: 16}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validGenerationSet(test.generations); got != test.valid {
				t.Fatalf("validGenerationSet(%v) = %t, want %t", test.generations, got, test.valid)
			}
		})
	}
}

func TestSnapshotMatch(t *testing.T) {
	result, err := decode(strings.NewReader(validResult))
	if err != nil {
		t.Fatal(err)
	}
	a := objectKey{kind: "block-device", rawDevice: 1}
	b := objectKey{kind: "block-device", rawDevice: 2}
	for _, test := range []struct {
		name, state string
		entries     []observation
		indices     []int
	}{
		{"empty", "not-observed", []observation{}, []int{}},
		{"single", "one-object", []observation{{result, a}}, []int{0}},
		{"alias", "one-object", []observation{{result, a}, {result, a}}, []int{0, 1}},
		{"clone", "conflicting-objects", []observation{{result, a}, {result, b}, {result, a}}, []int{0, 1, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := makeSnapshot(test.entries)
			if err != nil {
				t.Fatal(err)
			}
			match, err := snapshot.MatchUUID(result.FilesystemUUID)
			if err != nil || match.State != test.state || !reflect.DeepEqual(match.SourceIndices, test.indices) {
				t.Fatalf("match: %+v %v", match, err)
			}
			missing, err := snapshot.MatchUUID("11111111-2222-3333-4444-555555555555")
			if err != nil || missing.State != "not-observed" || len(missing.SourceIndices) != 0 {
				t.Fatal(missing, err)
			}
			copy := snapshot.Results()
			if len(copy) > 0 {
				copy[0] = Result{}
				if snapshot.Results()[0] != result {
					t.Fatal("mutable results")
				}
			}
		})
	}
	if _, err := (Snapshot{}).MatchUUID("not-an-uuid"); err == nil {
		t.Fatal("invalid query")
	}
	different := result
	different.FilesystemUUID = "11111111-2222-3333-4444-555555555555"
	if snapshot, err := makeSnapshot([]observation{{result, a}, {different, a}}); err == nil || len(snapshot.Results()) != 0 {
		t.Fatal("inconsistent same-object result")
	}
}

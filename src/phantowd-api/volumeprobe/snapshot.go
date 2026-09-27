// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import "os"

// MaxSources bounds retained descriptors and helper invocations per set.
const MaxSources = 32

// BlockDeviceGeneration is the transient kernel identity observed for one
// whole-disk block descriptor. DiskSequence is not a persistent media ID.
type BlockDeviceGeneration struct {
	Major        uint32
	Minor        uint32
	DiskSequence uint64
}

// ObservedBlockDevice carries only one kernel component name and its transient
// major/minor/diskseq tuple from a caller-validated whole-disk inventory. Name
// is a single /dev entry name, not an arbitrary path; the opener does not
// enumerate sysfs or establish that the caller is a trusted broker.
type ObservedBlockDevice struct {
	Name       string
	Generation BlockDeviceGeneration
}

// BlockDeviceSource pairs a caller-qualified whole-disk read-only descriptor
// with the major/minor and disk sequence previously observed for it.
type BlockDeviceSource struct {
	File       *os.File
	Generation BlockDeviceGeneration
}

func validateObservedBlockDevices(devices []ObservedBlockDevice) error {
	if devices == nil || len(devices) > MaxSources {
		return ErrUnsafe
	}
	generations := make([]BlockDeviceGeneration, len(devices))
	seenNames := make(map[string]bool, len(devices))
	seenGenerations := make(map[BlockDeviceGeneration]bool, len(devices))
	for index, device := range devices {
		if !validKernelBlockName(device.Name) || seenNames[device.Name] || seenGenerations[device.Generation] {
			return ErrUnsafe
		}
		seenNames[device.Name] = true
		seenGenerations[device.Generation] = true
		generations[index] = device.Generation
	}
	if !validGenerationSet(generations) {
		return ErrUnsafe
	}
	return nil
}

func validKernelBlockName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

// OrderCompleteBlockSources pairs exactly one descriptor source with every
// generation in an explicitly observed inventory, preserving inventory order.
// It only checks caller-provided metadata: callers must still verify each
// descriptor against the kernel and establish that the inventory is complete,
// eligible, and safe to inspect before using ObserveBlockSet.
func OrderCompleteBlockSources(
	inventory []BlockDeviceGeneration,
	sources []BlockDeviceSource,
) ([]BlockDeviceSource, error) {
	if inventory == nil || sources == nil || len(inventory) > MaxSources || len(sources) > MaxSources || len(inventory) != len(sources) || !validGenerationSet(inventory) {
		return nil, ErrUnsafe
	}

	indices := make(map[BlockDeviceGeneration]int, len(inventory))
	for index, generation := range inventory {
		if _, exists := indices[generation]; exists {
			return nil, ErrUnsafe
		}
		indices[generation] = index
	}

	ordered := make([]BlockDeviceSource, len(inventory))
	seenGenerations := make(map[BlockDeviceGeneration]bool, len(sources))
	seenFiles := make(map[*os.File]bool, len(sources))
	for _, source := range sources {
		index, observed := indices[source.Generation]
		if !observed || source.File == nil || seenGenerations[source.Generation] || seenFiles[source.File] {
			return nil, ErrUnsafe
		}
		seenGenerations[source.Generation] = true
		seenFiles[source.File] = true
		ordered[index] = source
	}
	if len(seenGenerations) != len(inventory) {
		return nil, ErrUnsafe
	}
	return ordered, nil
}

type objectKey struct {
	kind                     string
	device, inode, rawDevice uint64
}

type observation struct {
	result Result
	object objectKey
}

// Snapshot covers only supplied eligible descriptors, not complete discovery.
// It owns no descriptor on return and is not a storage lease. Its internal
// object keys are ephemeral comparisons, not persistent volume identifiers.
type Snapshot struct{ entries []observation }

// Match summarizes one UUID ONLY in this completed set. Even one-object does
// not establish global uniqueness, health, compatibility or mount permission.
type Match struct {
	State         string
	SourceIndices []int
}

// Results returns a copy in caller-supplied order. No path/serial is included;
// UUIDs remain private and must not be exposed in public diagnostics.
func (snapshot Snapshot) Results() []Result {
	results := make([]Result, len(snapshot.entries))
	for i, entry := range snapshot.entries {
		results[i] = entry.result
	}
	return results
}

// MatchUUID deliberately says not-observed, not absent/empty. Unidentified or
// omitted media may contain an intended volume; errors never yield a snapshot.
func (snapshot Snapshot) MatchUUID(uuid string) (Match, error) {
	if !validUUID(uuid) {
		return Match{}, ErrUnsafe
	}
	match := Match{State: "not-observed", SourceIndices: []int{}}
	objects := map[objectKey]bool{}
	for i, entry := range snapshot.entries {
		if entry.result.Status == "ext-metadata" && entry.result.FilesystemUUID == uuid {
			objects[entry.object] = true
			match.SourceIndices = append(match.SourceIndices, i)
		}
	}
	if len(objects) == 1 {
		match.State = "one-object"
	}
	if len(objects) > 1 {
		match.State = "conflicting-objects"
	}
	return match, nil
}

func makeSnapshot(entries []observation) (Snapshot, error) {
	seen := map[objectKey]Result{}
	for _, entry := range entries {
		if previous, ok := seen[entry.object]; ok && previous != entry.result {
			return Snapshot{}, ErrUnsafe // same pinned object gave inconsistent observations
		}
		seen[entry.object] = entry.result
	}
	return Snapshot{entries: append([]observation{}, entries...)}, nil
}

func validGenerationSet(generations []BlockDeviceGeneration) bool {
	type deviceNumber struct{ major, minor uint32 }
	byDevice := make(map[deviceNumber]uint64, len(generations))
	bySequence := make(map[uint64]deviceNumber, len(generations))
	for _, generation := range generations {
		if (generation.Major == 0 && generation.Minor == 0) || generation.DiskSequence == 0 {
			return false
		}
		device := deviceNumber{generation.Major, generation.Minor}
		if previous, ok := byDevice[device]; ok && previous != generation.DiskSequence {
			return false
		}
		if previous, ok := bySequence[generation.DiskSequence]; ok && previous != device {
			return false
		}
		byDevice[device] = generation.DiskSequence
		bySequence[generation.DiskSequence] = device
	}
	return true
}

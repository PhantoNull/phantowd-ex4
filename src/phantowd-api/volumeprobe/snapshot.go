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

// BlockDeviceSource pairs a caller-qualified whole-disk read-only descriptor
// with the major/minor and disk sequence previously observed for it.
type BlockDeviceSource struct {
	File       *os.File
	Generation BlockDeviceGeneration
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

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mdmetadata

import (
	"encoding/hex"
	"errors"
	"sort"
)

const (
	maxComponentEvidence      = 512
	maxComponentDiskIndex     = 4
	maxComponentPartition     = 128
	arrayFingerprintByteCount = 32
)

type ArrayComparisonStatus string

const (
	ArrayMetadataConsistent ArrayComparisonStatus = "metadata-consistent"
	ArrayIncomplete         ArrayComparisonStatus = "incomplete"
	ArrayDivergentEvents    ArrayComparisonStatus = "divergent-events"
	ArrayConflicting        ArrayComparisonStatus = "conflicting"
	ArrayAmbiguous          ArrayComparisonStatus = "ambiguous"
)

// ComponentEvidence binds one parser result to a bounded caller-assigned
// position in the candidate-disk set. DiskIndex is not a bay or kernel name;
// locations are transient, not stable identity or authorization. The caller
// remains responsible for supplying the complete trusted candidate set.
type ComponentEvidence struct {
	DiskIndex       uint32      `json:"-"`
	PartitionNumber uint32      `json:"-"`
	Observation     Observation `json:"-"`
}

// ArrayComparison contains only generic checksummed metadata agreement. The
// identity fingerprint is private and is never serialized.
type ArrayComparison struct {
	ArrayIdentityFingerprint string                `json:"-"`
	Status                   ArrayComparisonStatus `json:"-"`
	ArrayLevel               int32                 `json:"-"`
	ArrayLayout              uint32                `json:"-"`
	ArraySizeSectors         uint64                `json:"-"`
	ChunkSizeSectors         uint32                `json:"-"`
	ComponentDataSectors     uint64                `json:"-"`
	RAIDDisks                uint32                `json:"-"`
	MaxDevices               uint32                `json:"-"`
	ObservedActiveRoles      uint32                `json:"-"`
	MemberCount              uint32                `json:"-"`
	MissingActiveRoles       []uint32              `json:"-"`
}

// SetComparison is an internal all-input summary. It does not prove active
// array health, data synchronization, filesystem integrity, WD compatibility,
// or safety to assemble, mount, import, repair, or mutate media.
type SetComparison struct {
	CandidateComponents             uint32            `json:"-"`
	UnqualifiedComponents           uint32            `json:"-"`
	UnidentifiedCandidateComponents uint32            `json:"-"`
	Arrays                          []ArrayComparison `json:"-"`
}

var ErrInvalidComponentSet = errors.New("invalid MD v1.0 component set")

// CompareComponents compares at most 512 observations from a four-disk,
// 128-partition envelope. It groups only validated candidate superblocks with
// a nonzero array fingerprint and requires agreement on array-level fields,
// component data size, event counters, unique member identities/roles, and
// coverage of every active RAID role. The caller must establish completeness;
// this function performs no I/O and grants no assembly or mount authority.
func CompareComponents(components []ComponentEvidence) (SetComparison, error) {
	comparison := SetComparison{Arrays: []ArrayComparison{}}
	if len(components) > maxComponentEvidence {
		return comparison, ErrInvalidComponentSet
	}

	locations := make(map[[2]uint32]bool, len(components))
	groups := make(map[string][]Observation)
	for _, component := range components {
		if component.DiskIndex == 0 || component.DiskIndex > maxComponentDiskIndex ||
			component.PartitionNumber == 0 || component.PartitionNumber > maxComponentPartition {
			return SetComparison{}, ErrInvalidComponentSet
		}
		location := [2]uint32{component.DiskIndex, component.PartitionNumber}
		if locations[location] {
			return SetComparison{}, ErrInvalidComponentSet
		}
		locations[location] = true

		observation := component.Observation
		if observation.PartitionNumber != component.PartitionNumber || !validComponentObservation(observation) {
			comparison.UnqualifiedComponents++
			continue
		}
		comparison.CandidateComponents++
		if !validFingerprint(observation.ArrayIdentityFingerprint) {
			comparison.UnidentifiedCandidateComponents++
			continue
		}
		groups[observation.ArrayIdentityFingerprint] = append(groups[observation.ArrayIdentityFingerprint], observation)
	}

	identities := make([]string, 0, len(groups))
	for identity := range groups {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	for _, identity := range identities {
		comparison.Arrays = append(comparison.Arrays, compareArray(identity, groups[identity]))
	}
	return comparison, nil
}

func validComponentObservation(observation Observation) bool {
	if observation.Status != StatusCandidate || observation.MetadataVersion != "1.0" ||
		!observation.MetadataRead || observation.SuperblockChecksumStatus != "valid" || observation.FeatureMap != 0 ||
		(observation.ArrayIdentityFingerprint != "" && !validFingerprint(observation.ArrayIdentityFingerprint)) ||
		observation.MaxDevices == 0 || observation.MaxDevices > mdV1MaxDevices ||
		observation.RAIDDisks == 0 || observation.RAIDDisks > observation.MaxDevices ||
		observation.MemberNumber >= observation.MaxDevices || observation.ArraySizeSectors == 0 ||
		observation.ComponentDataSectors == 0 || !validFingerprint(observation.MemberIdentityFingerprint) {
		return false
	}
	switch {
	case observation.MemberRole < uint16(observation.RAIDDisks):
		return observation.MemberRoleDescription == "active-slot"
	case observation.MemberRole == mdV1RoleSpare:
		return observation.MemberRoleDescription == "spare"
	case observation.MemberRole == mdV1RoleFaulty:
		return observation.MemberRoleDescription == "faulty"
	case observation.MemberRole == mdV1RoleJournal:
		return observation.MemberRoleDescription == "journal"
	default:
		return false
	}
}

func validFingerprint(value string) bool {
	if len(value) != arrayFingerprintByteCount*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == arrayFingerprintByteCount && hex.EncodeToString(decoded) == value
}

func compareArray(identity string, members []Observation) ArrayComparison {
	first := members[0]
	array := ArrayComparison{
		ArrayIdentityFingerprint: identity,
		Status:                   ArrayMetadataConsistent,
		ArrayLevel:               first.ArrayLevel,
		ArrayLayout:              first.ArrayLayout,
		ArraySizeSectors:         first.ArraySizeSectors,
		ChunkSizeSectors:         first.ChunkSizeSectors,
		ComponentDataSectors:     first.ComponentDataSectors,
		RAIDDisks:                first.RAIDDisks,
		MaxDevices:               first.MaxDevices,
		MemberCount:              uint32(len(members)),
		MissingActiveRoles:       []uint32{},
	}

	activeRoles := make(map[uint32]bool, array.RAIDDisks)
	memberNumbers := make(map[uint32]bool, len(members))
	memberIdentities := make(map[string]bool, len(members))
	duplicate, conflicting, divergent := false, false, false
	for _, current := range members {
		if current.ArrayLevel != first.ArrayLevel || current.ArrayLayout != first.ArrayLayout ||
			current.ArraySizeSectors != first.ArraySizeSectors || current.ChunkSizeSectors != first.ChunkSizeSectors ||
			current.ComponentDataSectors != first.ComponentDataSectors ||
			current.RAIDDisks != first.RAIDDisks || current.MaxDevices != first.MaxDevices ||
			current.FeatureMap != first.FeatureMap {
			conflicting = true
		}
		if current.Events != first.Events {
			divergent = true
		}
		if memberNumbers[current.MemberNumber] {
			duplicate = true
		}
		memberNumbers[current.MemberNumber] = true
		if current.MemberIdentityFingerprint != "" {
			if memberIdentities[current.MemberIdentityFingerprint] {
				duplicate = true
			}
			memberIdentities[current.MemberIdentityFingerprint] = true
		}
		if current.MemberRoleDescription == "active-slot" && uint32(current.MemberRole) < array.RAIDDisks {
			role := uint32(current.MemberRole)
			if activeRoles[role] {
				duplicate = true
			}
			activeRoles[role] = true
		}
	}
	for role := uint32(0); role < array.RAIDDisks; role++ {
		if activeRoles[role] {
			array.ObservedActiveRoles++
		} else {
			array.MissingActiveRoles = append(array.MissingActiveRoles, role)
		}
	}
	switch {
	case duplicate:
		array.Status = ArrayAmbiguous
	case conflicting:
		array.Status = ArrayConflicting
	case divergent:
		array.Status = ArrayDivergentEvents
	case len(array.MissingActiveRoles) != 0:
		array.Status = ArrayIncomplete
	}
	return array
}

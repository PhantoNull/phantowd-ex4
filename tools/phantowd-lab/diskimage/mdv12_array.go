// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"errors"
	"fmt"
	"sort"
)

const maxMDV12ImageSetComponents = 512

type MDV12ArrayStatus string

const (
	MDV12ArrayMetadataConsistent MDV12ArrayStatus = "metadata-consistent"
	MDV12ArrayIncomplete         MDV12ArrayStatus = "incomplete"
	MDV12ArrayDivergent          MDV12ArrayStatus = "divergent-events"
	MDV12ArrayConflicting        MDV12ArrayStatus = "conflicting"
	MDV12ArrayAmbiguous          MDV12ArrayStatus = "ambiguous"
)

// MDV12ImageComponent links one parsed component observation to an ordinal
// input-image and partition number. It deliberately contains no host path.
type MDV12ImageComponent struct {
	InputIndex      int
	PartitionNumber int
	Report          MDV12Report
}

type MDV12ImageSetReport struct {
	Format                          string              `json:"format"`
	SchemaVersion                   int                 `json:"schema_version"`
	WDCompatibility                 string              `json:"wd_compatibility"`
	CandidateComponents             int                 `json:"candidate_components"`
	UnqualifiedComponents           int                 `json:"unqualified_components"`
	UnidentifiedCandidateComponents int                 `json:"unidentified_candidate_components"`
	Arrays                          []MDV12ArraySummary `json:"arrays"`
	BlockDeviceOpened               bool                `json:"block_device_opened"`
	MutationsPerformed              bool                `json:"mutations_performed"`
	AssemblyPerformed               bool                `json:"assembly_performed"`
	MountPerformed                  bool                `json:"mount_performed"`
	Limitations                     []string            `json:"limitations"`
}

type MDV12ArraySummary struct {
	ArrayIdentityFingerprint string             `json:"array_identity_fingerprint"`
	WDCompatibility          string             `json:"wd_compatibility"`
	Status                   MDV12ArrayStatus   `json:"status"`
	ArrayLevel               int32              `json:"array_level"`
	ArrayLayout              uint32             `json:"array_layout"`
	ArraySizeSectors         uint64             `json:"array_size_sectors"`
	ChunkSizeSectors         uint32             `json:"chunk_size_sectors"`
	RAIDDisks                uint32             `json:"raid_disks"`
	MaxDevices               uint32             `json:"max_devices"`
	FeatureMap               uint32             `json:"feature_map"`
	ObservedActiveRoles      int                `json:"observed_active_roles"`
	MissingActiveRoles       []uint32           `json:"missing_active_roles"`
	Members                  []MDV12ArrayMember `json:"members"`
	Findings                 []string           `json:"findings"`
}

type MDV12ArrayMember struct {
	InputIndex                int    `json:"input_index"`
	PartitionNumber           int    `json:"partition_number"`
	MemberNumber              uint32 `json:"member_number"`
	Role                      uint16 `json:"role"`
	MemberIdentityFingerprint string `json:"member_identity_fingerprint,omitempty"`
	Events                    uint64 `json:"events"`
}

// CompareMDV12ImageSet groups bounded MD v1.2 observations from caller-owned
// disk images and reports only metadata agreement. It never opens devices,
// assembles arrays, mounts filesystems, or authorizes migration.
func CompareMDV12ImageSet(components []MDV12ImageComponent) (MDV12ImageSetReport, error) {
	report := MDV12ImageSetReport{
		Format:          "phantowd-md-v1.2-image-set-inspection",
		SchemaVersion:   1,
		WDCompatibility: "unqualified",
		Arrays:          []MDV12ArraySummary{},
		Limitations: []string{
			"only caller-selected regular-file images and their parsed MD v1.2 components are compared; WD XML, other metadata versions, filesystem integrity, disk health, and user data are not inspected",
			"metadata-consistent means only that the observed checksummed components agree on selected fields and cover active RAID roles; it does not establish sync state, health, WD compatibility, import safety, or recovery",
			"per-device replacement, bitmap, recovery, reshape, bad-block, journal, and other feature semantics are not interpreted; a nonzero feature map requires separate review",
			"raw image paths and on-disk identifiers are not returned; fingerprints are redaction aids, not authenticity checks",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no input image is modified",
		},
	}
	if len(components) > maxMDV12ImageSetComponents {
		return report, errors.New("too many MD v1.2 components in image set")
	}

	locations := make(map[[2]int]bool, len(components))
	groups := make(map[string][]MDV12ImageComponent)
	for _, component := range components {
		if component.InputIndex < 1 || component.InputIndex > 4 ||
			component.PartitionNumber < 1 || component.PartitionNumber > 128 {
			return report, errors.New("MD v1.2 component location is outside the bounded EX4 image-set range")
		}
		location := [2]int{component.InputIndex, component.PartitionNumber}
		if locations[location] {
			return report, errors.New("duplicate MD v1.2 component location")
		}
		locations[location] = true
		if component.Report.Status != MDStatusCandidate || component.Report.MetadataVersion != "1.2" ||
			component.Report.SuperblockChecksumStatus != "valid" {
			report.UnqualifiedComponents++
			continue
		}
		report.CandidateComponents++
		if component.Report.ArrayIdentityFingerprint == "" {
			report.UnidentifiedCandidateComponents++
			continue
		}
		groups[component.Report.ArrayIdentityFingerprint] = append(groups[component.Report.ArrayIdentityFingerprint], component)
	}

	identities := make([]string, 0, len(groups))
	for identity := range groups {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	for _, identity := range identities {
		group := groups[identity]
		sort.Slice(group, func(i, j int) bool {
			if group[i].InputIndex != group[j].InputIndex {
				return group[i].InputIndex < group[j].InputIndex
			}
			return group[i].PartitionNumber < group[j].PartitionNumber
		})
		report.Arrays = append(report.Arrays, compareMDV12ArrayGroup(identity, group))
	}
	return report, nil
}

func compareMDV12ArrayGroup(identity string, components []MDV12ImageComponent) MDV12ArraySummary {
	first := components[0].Report
	array := MDV12ArraySummary{
		ArrayIdentityFingerprint: identity,
		WDCompatibility:          "unqualified",
		Status:                   MDV12ArrayMetadataConsistent,
		ArrayLevel:               first.ArrayLevel,
		ArrayLayout:              first.ArrayLayout,
		ArraySizeSectors:         first.ArraySizeSectors,
		ChunkSizeSectors:         first.ChunkSizeSectors,
		RAIDDisks:                first.RAIDDisks,
		MaxDevices:               first.MaxDevices,
		FeatureMap:               first.FeatureMap,
		MissingActiveRoles:       []uint32{},
		Members:                  []MDV12ArrayMember{},
		Findings:                 []string{},
	}
	if array.RAIDDisks == 0 || array.RAIDDisks > array.MaxDevices {
		arrayFindings := []string{"component reports an invalid RAID-disk or maximum-device count"}
		array.Status = MDV12ArrayConflicting
		array.Findings = arrayFindings
		return array
	}

	activeRoles := make(map[uint32]bool, array.RAIDDisks)
	memberNumbers := make(map[uint32]bool, len(components))
	memberIdentities := make(map[string]bool, len(components))
	duplicate := false
	conflicting := false
	divergent := false
	for _, component := range components {
		current := component.Report
		if current.ArrayLevel != first.ArrayLevel || current.ArrayLayout != first.ArrayLayout ||
			current.ArraySizeSectors != first.ArraySizeSectors || current.ChunkSizeSectors != first.ChunkSizeSectors ||
			current.RAIDDisks != first.RAIDDisks || current.MaxDevices != first.MaxDevices || current.FeatureMap != first.FeatureMap {
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
		array.Members = append(array.Members, MDV12ArrayMember{
			InputIndex: component.InputIndex, PartitionNumber: component.PartitionNumber,
			MemberNumber: current.MemberNumber, Role: current.MemberRole,
			MemberIdentityFingerprint: current.MemberIdentityFingerprint, Events: current.Events,
		})
	}
	for role := uint32(0); role < array.RAIDDisks; role++ {
		if activeRoles[role] {
			array.ObservedActiveRoles++
		} else {
			array.MissingActiveRoles = append(array.MissingActiveRoles, role)
		}
	}
	if duplicate {
		array.Findings = append(array.Findings, "duplicate member number, device identity, or active RAID role is present")
	}
	if conflicting {
		array.Findings = append(array.Findings, "array-level fields disagree across component superblocks")
	}
	if divergent {
		array.Findings = append(array.Findings, "component superblock event counters differ; stale or interrupted metadata requires separate analysis")
	}
	if len(array.MissingActiveRoles) != 0 {
		array.Findings = append(array.Findings, fmt.Sprintf("%d active RAID role(s) are missing from the supplied image set", len(array.MissingActiveRoles)))
	}
	switch {
	case duplicate:
		array.Status = MDV12ArrayAmbiguous
	case conflicting:
		array.Status = MDV12ArrayConflicting
	case divergent:
		array.Status = MDV12ArrayDivergent
	case len(array.MissingActiveRoles) != 0:
		array.Status = MDV12ArrayIncomplete
	}
	if array.Status == MDV12ArrayMetadataConsistent {
		array.Findings = append(array.Findings, "checksummed components agree on selected array fields and cover each active role; this is not proof of data synchronization or array health")
	}
	if array.FeatureMap != 0 {
		array.Findings = append(array.Findings, "nonzero feature_map is reported but feature semantics are not qualified by this comparator")
	}
	return array
}

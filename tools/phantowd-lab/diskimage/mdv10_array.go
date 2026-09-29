// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"errors"
	"fmt"
	"sort"
)

const maxMDV10ImageSetComponents = 512

type MDV10ImageComponent struct {
	InputIndex      int
	PartitionNumber int
	Report          MDV10Report
}

type MDV10ArrayStatus string

const (
	MDV10ArrayMetadataConsistent MDV10ArrayStatus = "metadata-consistent"
	MDV10ArrayIncomplete         MDV10ArrayStatus = "incomplete"
	MDV10ArrayDivergent          MDV10ArrayStatus = "divergent-events"
	MDV10ArrayConflicting        MDV10ArrayStatus = "conflicting"
	MDV10ArrayAmbiguous          MDV10ArrayStatus = "ambiguous"
)

type MDV10ImageSetReport struct {
	Format                          string              `json:"format"`
	SchemaVersion                   int                 `json:"schema_version"`
	WDCompatibility                 string              `json:"wd_compatibility"`
	CandidateComponents             int                 `json:"candidate_components"`
	UnqualifiedComponents           int                 `json:"unqualified_components"`
	UnidentifiedCandidateComponents int                 `json:"unidentified_candidate_components"`
	Arrays                          []MDV10ArraySummary `json:"arrays"`
	BlockDeviceOpened               bool                `json:"block_device_opened"`
	MutationsPerformed              bool                `json:"mutations_performed"`
	AssemblyPerformed               bool                `json:"assembly_performed"`
	MountPerformed                  bool                `json:"mount_performed"`
	Limitations                     []string            `json:"limitations"`
}

type MDV10ArraySummary struct {
	ArrayIdentityFingerprint string             `json:"array_identity_fingerprint"`
	WDCompatibility          string             `json:"wd_compatibility"`
	Status                   MDV10ArrayStatus   `json:"status"`
	ArrayLevel               int32              `json:"array_level"`
	ArrayLayout              uint32             `json:"array_layout"`
	ArraySizeSectors         uint64             `json:"array_size_sectors"`
	ChunkSizeSectors         uint32             `json:"chunk_size_sectors"`
	RAIDDisks                uint32             `json:"raid_disks"`
	MaxDevices               uint32             `json:"max_devices"`
	FeatureMap               uint32             `json:"feature_map"`
	ObservedActiveRoles      int                `json:"observed_active_roles"`
	MissingActiveRoles       []uint32           `json:"missing_active_roles"`
	Members                  []MDV10ArrayMember `json:"members"`
	Findings                 []string           `json:"findings"`
}

type MDV10ArrayMember struct {
	InputIndex                int    `json:"input_index"`
	PartitionNumber           int    `json:"partition_number"`
	MemberNumber              uint32 `json:"member_number"`
	Role                      uint16 `json:"role"`
	MemberIdentityFingerprint string `json:"member_identity_fingerprint,omitempty"`
	Events                    uint64 `json:"events"`
}

// CompareMDV10ImageSet groups bounded generic MD 1.0 observations from
// caller-owned whole-disk images and reports selected metadata agreement only.
// It never opens devices, assembles arrays, mounts filesystems, modifies images,
// or qualifies WD compatibility.
func CompareMDV10ImageSet(components []MDV10ImageComponent) (MDV10ImageSetReport, error) {
	report := MDV10ImageSetReport{
		Format:          "phantowd-md-v1.0-image-set-inspection",
		SchemaVersion:   1,
		WDCompatibility: "unqualified",
		Arrays:          []MDV10ArraySummary{},
		Limitations: []string{
			"only caller-selected regular-file images and their parsed MD v1.0 components are compared; WD XML, other metadata versions, filesystem integrity, disk health, and user data are not inspected",
			"metadata-consistent means only that observed checksummed components agree on selected fields and cover active RAID roles; it does not establish sync state, health, WD compatibility, import safety, or recovery",
			"per-device replacement, bitmap, recovery, reshape, bad-block, journal, and other feature semantics are not interpreted; a nonzero feature map requires separate review",
			"raw image paths and on-disk identifiers are not returned; fingerprints are redaction aids, not authenticity checks",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no input image is modified",
		},
	}
	if len(components) > maxMDV10ImageSetComponents {
		return report, errors.New("too many MD v1.0 components in image set")
	}

	locations := make(map[[2]int]bool, len(components))
	groups := make(map[string][]MDV10ImageComponent)
	for _, component := range components {
		if component.InputIndex < 1 || component.InputIndex > 4 ||
			component.PartitionNumber < 1 || component.PartitionNumber > 128 {
			return report, errors.New("MD v1.0 component location is outside the bounded EX4 image-set range")
		}
		location := [2]int{component.InputIndex, component.PartitionNumber}
		if locations[location] {
			return report, errors.New("duplicate MD v1.0 component location")
		}
		locations[location] = true
		if !validMDV10Component(component.Report) {
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
		report.Arrays = append(report.Arrays, compareMDV10ArrayGroup(identity, group))
	}
	return report, nil
}

func validMDV10Component(report MDV10Report) bool {
	if report.Status != MDV10StatusCandidate || report.SchemaVersion != 1 || report.MetadataVersion != "1.0" ||
		report.SuperblockChecksumStatus != "valid" || report.MaxDevices == 0 || report.MaxDevices > mdV1MaxDevices ||
		report.RAIDDisks == 0 || report.RAIDDisks > report.MaxDevices || report.MemberNumber >= report.MaxDevices {
		return false
	}
	switch {
	case report.MemberRole < uint16(report.RAIDDisks):
		return report.MemberRoleDescription == "active-slot"
	case report.MemberRole == mdV1RoleSpare:
		return report.MemberRoleDescription == "spare"
	case report.MemberRole == mdV1RoleFaulty:
		return report.MemberRoleDescription == "faulty"
	case report.MemberRole == mdV1RoleJournal:
		return report.MemberRoleDescription == "journal"
	default:
		return false
	}
}

func compareMDV10ArrayGroup(identity string, components []MDV10ImageComponent) MDV10ArraySummary {
	first := components[0].Report
	array := MDV10ArraySummary{
		ArrayIdentityFingerprint: identity, WDCompatibility: "unqualified",
		Status: MDV10ArrayMetadataConsistent, ArrayLevel: first.ArrayLevel,
		ArrayLayout: first.ArrayLayout, ArraySizeSectors: first.ArraySizeSectors,
		ChunkSizeSectors: first.ChunkSizeSectors, RAIDDisks: first.RAIDDisks,
		MaxDevices: first.MaxDevices, FeatureMap: first.FeatureMap,
		MissingActiveRoles: []uint32{}, Members: []MDV10ArrayMember{}, Findings: []string{},
	}
	activeRoles := make(map[uint32]bool, array.RAIDDisks)
	memberNumbers := make(map[uint32]bool, len(components))
	memberIdentities := make(map[string]bool, len(components))
	duplicate, conflicting, divergent := false, false, false
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
		array.Members = append(array.Members, MDV10ArrayMember{
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
		array.Findings = append(array.Findings, "duplicate member number, identity, or active RAID role is present")
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
		array.Status = MDV10ArrayAmbiguous
	case conflicting:
		array.Status = MDV10ArrayConflicting
	case divergent:
		array.Status = MDV10ArrayDivergent
	case len(array.MissingActiveRoles) != 0:
		array.Status = MDV10ArrayIncomplete
	}
	if array.Status == MDV10ArrayMetadataConsistent {
		array.Findings = append(array.Findings, "checksummed components agree on selected array fields and cover each active role; this is not proof of data synchronization or array health")
	}
	if array.FeatureMap != 0 {
		array.Findings = append(array.Findings, "nonzero feature_map is reported but feature semantics are not qualified by this comparator")
		if array.Status == MDV10ArrayMetadataConsistent {
			array.Status = MDV10ArrayIncomplete
		}
	}
	return array
}

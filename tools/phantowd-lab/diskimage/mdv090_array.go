// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"errors"
	"fmt"
	"sort"
)

const maxMDV090ImageSetComponents = 512

type MDV090ArrayStatus string

const (
	MDV090ArrayMetadataConsistent MDV090ArrayStatus = "metadata-consistent"
	MDV090ArrayIncomplete         MDV090ArrayStatus = "incomplete"
	MDV090ArrayDivergent          MDV090ArrayStatus = "divergent-events"
	MDV090ArrayConflicting        MDV090ArrayStatus = "conflicting"
	MDV090ArrayAmbiguous          MDV090ArrayStatus = "ambiguous"
)

// MDV090ImageComponent links one parsed component observation to its input
// image and GPT partition ordinal. It deliberately contains no host path.
type MDV090ImageComponent struct {
	InputIndex      int
	PartitionNumber int
	Report          MDV090Report
}

type MDV090ImageSetReport struct {
	Format                          string               `json:"format"`
	SchemaVersion                   int                  `json:"schema_version"`
	WDCompatibility                 string               `json:"wd_compatibility"`
	CandidateComponents             int                  `json:"candidate_components"`
	UnqualifiedComponents           int                  `json:"unqualified_components"`
	UnidentifiedCandidateComponents int                  `json:"unidentified_candidate_components"`
	Arrays                          []MDV090ArraySummary `json:"arrays"`
	BlockDeviceOpened               bool                 `json:"block_device_opened"`
	MutationsPerformed              bool                 `json:"mutations_performed"`
	AssemblyPerformed               bool                 `json:"assembly_performed"`
	MountPerformed                  bool                 `json:"mount_performed"`
	Limitations                     []string             `json:"limitations"`
}

type MDV090ArraySummary struct {
	ArrayIdentityFingerprint string              `json:"array_identity_fingerprint"`
	WDCompatibility          string              `json:"wd_compatibility"`
	Status                   MDV090ArrayStatus   `json:"status"`
	ArrayLevel               int32               `json:"array_level"`
	RAIDDisks                uint32              `json:"raid_disks"`
	ObservedNRDisks          []uint32            `json:"observed_nr_disks"`
	ObservedRAIDRoles        int                 `json:"observed_raid_roles"`
	MissingRAIDRoles         []uint32            `json:"missing_raid_roles"`
	Members                  []MDV090ArrayMember `json:"members"`
	Findings                 []string            `json:"findings"`
}

type MDV090ArrayMember struct {
	InputIndex      int    `json:"input_index"`
	PartitionNumber int    `json:"partition_number"`
	MemberNumber    uint32 `json:"member_number"`
	NRDisks         uint32 `json:"nr_disks"`
	Role            uint32 `json:"role"`
	RoleDescription string `json:"role_description"`
	Events          uint64 `json:"events"`
}

// CompareMDV090ImageSet compares bounded generic MD 0.90 observations from
// caller-owned whole-disk images. It reports selected metadata agreement only:
// it never opens block devices, assembles arrays, mounts filesystems, modifies
// an image, or qualifies a WD disk layout.
func CompareMDV090ImageSet(components []MDV090ImageComponent) (MDV090ImageSetReport, error) {
	report := MDV090ImageSetReport{
		Format:          "phantowd-md-v0.90-image-set-inspection",
		SchemaVersion:   1,
		WDCompatibility: "unqualified",
		Arrays:          []MDV090ArraySummary{},
		Limitations: []string{
			"only caller-selected regular-file images and their parsed MD 0.90 components are compared; WD XML, other metadata versions, filesystem integrity, disk health, and user data are not inspected",
			"metadata-consistent means only that observed components agree on selected constant fields and cover assigned RAID slots; it does not establish member operational state, sync state, health, WD compatibility, import safety, or recovery",
			"the comparator reads the per-component assigned role but not the MD 0.90 disk descriptor state table, so a reported RAID slot is not evidence that a member is active or in sync",
			"member identity and replacement/recovery semantics beyond the legacy member number and role are not available in this report",
			"raw image paths and on-disk identifiers are not returned; fingerprints are redaction aids, not authenticity checks",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no input image is modified",
		},
	}
	if len(components) > maxMDV090ImageSetComponents {
		return report, errors.New("too many MD 0.90 components in image set")
	}

	locations := make(map[[2]int]bool, len(components))
	groups := make(map[string][]MDV090ImageComponent)
	for _, component := range components {
		if component.InputIndex < 1 || component.InputIndex > 4 ||
			component.PartitionNumber < 1 || component.PartitionNumber > 128 {
			return report, errors.New("MD 0.90 component location is outside the bounded EX4 image-set range")
		}
		location := [2]int{component.InputIndex, component.PartitionNumber}
		if locations[location] {
			return report, errors.New("duplicate MD 0.90 component location")
		}
		locations[location] = true
		if component.Report.Status != MDV090StatusCandidate || component.Report.MetadataVersion != "0.90" ||
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
		report.Arrays = append(report.Arrays, compareMDV090ArrayGroup(identity, group))
	}
	return report, nil
}

func compareMDV090ArrayGroup(identity string, components []MDV090ImageComponent) MDV090ArraySummary {
	first := components[0].Report
	array := MDV090ArraySummary{
		ArrayIdentityFingerprint: identity,
		WDCompatibility:          "unqualified",
		Status:                   MDV090ArrayMetadataConsistent,
		ArrayLevel:               first.ArrayLevel,
		RAIDDisks:                first.RAIDDisks,
		ObservedNRDisks:          []uint32{},
		MissingRAIDRoles:         []uint32{},
		Members:                  []MDV090ArrayMember{},
		Findings:                 []string{},
	}
	if array.RAIDDisks == 0 || array.RAIDDisks > mdV090MaxDevices {
		array.Status = MDV090ArrayConflicting
		array.Findings = []string{"component reports a RAID-disk count outside the MD 0.90 metadata limit"}
		return array
	}
	activeRoles := make(map[uint32]bool, array.RAIDDisks)
	memberNumbers := make(map[uint32]bool, len(components))
	nrDisksSeen := make(map[uint32]bool, len(components))
	duplicate := false
	conflicting := false
	divergent := false
	invalidCounts := false
	for _, component := range components {
		current := component.Report
		if current.NRDisks == 0 || current.NRDisks > mdV090MaxDevices ||
			current.RAIDDisks == 0 || current.RAIDDisks > current.NRDisks ||
			current.MemberNumber >= current.NRDisks {
			invalidCounts = true
		}
		if current.ArrayLevel != first.ArrayLevel || current.RAIDDisks != first.RAIDDisks {
			conflicting = true
		}
		if current.Events != first.Events {
			divergent = true
		}
		if memberNumbers[current.MemberNumber] {
			duplicate = true
		}
		memberNumbers[current.MemberNumber] = true
		nrDisksSeen[current.NRDisks] = true
		if current.MemberRoleDescription == "raid-slot" && current.MemberRole < array.RAIDDisks {
			if activeRoles[current.MemberRole] {
				duplicate = true
			}
			activeRoles[current.MemberRole] = true
		}
		array.Members = append(array.Members, MDV090ArrayMember{
			InputIndex: component.InputIndex, PartitionNumber: component.PartitionNumber,
			MemberNumber: current.MemberNumber, NRDisks: current.NRDisks, Role: current.MemberRole,
			RoleDescription: current.MemberRoleDescription, Events: current.Events,
		})
	}
	for count := range nrDisksSeen {
		array.ObservedNRDisks = append(array.ObservedNRDisks, count)
	}
	sort.Slice(array.ObservedNRDisks, func(i, j int) bool {
		return array.ObservedNRDisks[i] < array.ObservedNRDisks[j]
	})
	for role := uint32(0); role < array.RAIDDisks; role++ {
		if activeRoles[role] {
			array.ObservedRAIDRoles++
		} else {
			array.MissingRAIDRoles = append(array.MissingRAIDRoles, role)
		}
	}
	if duplicate {
		array.Findings = append(array.Findings, "duplicate member number or assigned RAID slot is present")
	}
	if conflicting {
		array.Findings = append(array.Findings, "array-level fields disagree across component superblocks")
	}
	if invalidCounts {
		array.Findings = append(array.Findings, "one or more components report invalid member or RAID-disk counts")
	}
	if len(array.ObservedNRDisks) > 1 {
		array.Findings = append(array.Findings, "component nr_disks values differ; Linux MD 0.90 does not treat nr_disks as a constant array field")
	}
	if divergent {
		array.Findings = append(array.Findings, "component superblock event counters differ; stale or interrupted metadata requires separate analysis")
	}
	if len(array.MissingRAIDRoles) != 0 {
		array.Findings = append(array.Findings, fmt.Sprintf("%d assigned RAID slot(s) are missing from the supplied image set", len(array.MissingRAIDRoles)))
	}
	switch {
	case duplicate:
		array.Status = MDV090ArrayAmbiguous
	case conflicting || invalidCounts:
		array.Status = MDV090ArrayConflicting
	case divergent:
		array.Status = MDV090ArrayDivergent
	case len(array.MissingRAIDRoles) != 0:
		array.Status = MDV090ArrayIncomplete
	}
	if array.Status == MDV090ArrayMetadataConsistent {
		array.Findings = append(array.Findings, "components agree on selected constant MD 0.90 fields and cover each assigned RAID slot; device state, data synchronization, and array health remain unqualified")
	}
	return array
}

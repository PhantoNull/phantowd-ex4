// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"

const (
	gptIdentityCoverageEmpty         = "empty-candidate-set"
	gptIdentityCoverageNone          = "no-gpt-candidates"
	gptIdentityCoveragePartial       = "partial-gpt-candidates"
	gptIdentityCoverageAllCandidates = "all-candidates-gpt"

	gptIdentitySingletonObserved = "singleton-in-observed-gpt-candidates"
	gptIdentityAmbiguousObserved = "ambiguous-in-observed-gpt-candidates"
)

// gptIdentitySetObservation reports collisions only within a complete trusted
// candidate snapshot. A singleton status is not a global uniqueness claim.
// All fields stay internal and cannot be serialized to API JSON.
type gptIdentitySetObservation struct {
	CandidateCount                int                    `json:"-"`
	GPTDiskCount                  int                    `json:"-"`
	UnsupportedTableCount         int                    `json:"-"`
	NoTableCount                  int                    `json:"-"`
	Coverage                      string                 `json:"-"`
	VPDIdentityAmbiguous          bool                   `json:"-"`
	VPDIdentityEvidenceIncomplete bool                   `json:"-"`
	Bindings                      []diskPartitionBinding `json:"-"`
}

type partitionIdentityReference struct {
	diskIndex      int
	partitionIndex int
}

// observeCandidateGPTIdentities rechecks the entire trusted snapshot and the
// generation-bound descriptor results before classifying IDs. MBR remains an
// unsupported table disposition; GPT singletons are scoped to the observed GPT
// subset and never prove global uniqueness or permit persistence/mount/import.
func observeCandidateGPTIdentities(
	discovery *trustedStorageDiscovery,
	current storageSnapshot,
	results []volumeprobe.Result,
) (gptIdentitySetObservation, error) {
	bindings, err := correlateCandidatePartitionTables(discovery, current, results)
	if err != nil {
		return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
	}
	observation, err := classifyGPTPartitionIdentities(bindings)
	if err != nil {
		return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
	}
	observation.VPDIdentityAmbiguous = discovery.hasAmbiguousIdentity
	observation.VPDIdentityEvidenceIncomplete = discovery.identityEvidenceIncomplete
	return observation, nil
}

// classifyGPTPartitionIdentities compares validated on-disk IDs from one
// caller-supplied binding set. Its singleton label is intentionally limited to
// that set; only observeCandidateGPTIdentities binds it to trusted completeness.
func classifyGPTPartitionIdentities(bindings []diskPartitionBinding) (gptIdentitySetObservation, error) {
	if bindings == nil || len(bindings) > maxBlockEntries {
		return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
	}
	observation := gptIdentitySetObservation{
		CandidateCount: len(bindings),
		Bindings:       append([]diskPartitionBinding(nil), bindings...),
	}
	for index := range observation.Bindings {
		observation.Bindings[index].Partitions = append([]kernelPartitionBinding(nil), bindings[index].Partitions...)
	}
	seenNames := make(map[string]bool, len(bindings))
	seenGenerations := make(map[volumeprobe.BlockDeviceGeneration]bool, len(bindings))
	seenDeviceNumbers := make(map[observedDeviceNumber]bool, len(bindings))
	seenPartitionNames := make(map[string]bool)
	diskGUIDOwners := make(map[string][]int)
	partUUIDOwners := make(map[string][]partitionIdentityReference)

	for diskIndex := range observation.Bindings {
		binding := &observation.Bindings[diskIndex]
		generation := binding.Generation
		if !validBlockName(binding.DiskName) || seenNames[binding.DiskName] ||
			(generation.Major == 0 && generation.Minor == 0) || generation.DiskSequence == 0 ||
			seenGenerations[generation] {
			return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
		}
		seenNames[binding.DiskName] = true
		seenGenerations[generation] = true
		diskDeviceNumber := observedDeviceNumber{major: generation.Major, minor: generation.Minor}
		if seenDeviceNumbers[diskDeviceNumber] {
			return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
		}
		seenDeviceNumbers[diskDeviceNumber] = true

		switch binding.TableDisposition {
		case partitionTableNoTable:
			if binding.Scheme != "" || binding.TableID != "" || len(binding.Partitions) != 0 {
				return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
			}
			observation.NoTableCount++
		case partitionTableUnsupported:
			if binding.Scheme != "" || binding.TableID != "" || len(binding.Partitions) != 0 {
				return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
			}
			observation.UnsupportedTableCount++
		case partitionTableGPT:
			if binding.Scheme != "gpt" || binding.TableID == "" {
				return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
			}
			observation.GPTDiskCount++
			binding.TableIDStatus = gptIdentitySingletonObserved
			diskGUIDOwners[binding.TableID] = append(diskGUIDOwners[binding.TableID], diskIndex)

			seenPartUUIDs := make(map[string]bool, len(binding.Partitions))
			for partitionIndex := range binding.Partitions {
				partition := &binding.Partitions[partitionIndex]
				partitionDeviceNumber := observedDeviceNumber{major: partition.Major, minor: partition.Minor}
				if !validBlockName(partition.KernelName) || seenPartitionNames[partition.KernelName] ||
					(partition.Major == 0 && partition.Minor == 0) || seenDeviceNumbers[partitionDeviceNumber] ||
					partition.UUID == "" || partition.Number == 0 || seenPartUUIDs[partition.UUID] {
					return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
				}
				seenPartitionNames[partition.KernelName] = true
				seenDeviceNumbers[partitionDeviceNumber] = true
				seenPartUUIDs[partition.UUID] = true
				partition.UUIDStatus = gptIdentitySingletonObserved
				partUUIDOwners[partition.UUID] = append(partUUIDOwners[partition.UUID], partitionIdentityReference{
					diskIndex: diskIndex, partitionIndex: partitionIndex,
				})
			}
		default:
			return gptIdentitySetObservation{}, errStorageDiscoveryIncomplete
		}
	}

	for _, owners := range diskGUIDOwners {
		if len(owners) < 2 {
			continue
		}
		for _, diskIndex := range owners {
			observation.Bindings[diskIndex].TableIDStatus = gptIdentityAmbiguousObserved
		}
	}
	for _, owners := range partUUIDOwners {
		if len(owners) < 2 {
			continue
		}
		for _, owner := range owners {
			observation.Bindings[owner.diskIndex].Partitions[owner.partitionIndex].UUIDStatus = gptIdentityAmbiguousObserved
		}
	}

	switch {
	case observation.CandidateCount == 0:
		observation.Coverage = gptIdentityCoverageEmpty
	case observation.GPTDiskCount == 0:
		observation.Coverage = gptIdentityCoverageNone
	case observation.GPTDiskCount == observation.CandidateCount:
		observation.Coverage = gptIdentityCoverageAllCandidates
	default:
		observation.Coverage = gptIdentityCoveragePartial
	}
	return observation, nil
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"

var storageMDV10ObservationLimitations = [...]string{
	"only complete eligible GPT candidate disks and GPT-declared Linux RAID member partitions were considered",
	"MD v1.0 metadata agreement is not array health, synchronization, filesystem integrity, WD compatibility or bay mapping",
	"array metadata identities, member identities, raw GUIDs, kernel names and device paths are not included in this result",
	"no filesystem data was read; no array was assembled, mounted, imported, repaired or modified",
	"cancellation cannot guarantee prompt recovery from uninterruptible kernel block I/O; this is not EX4 hardware qualification",
}

// storageMDV10ObservationSummary is the only MD v1.0 observation payload
// allowed across the storage broker boundary. It deliberately reports counts
// and bounded limitations only: no identities, locations, fingerprints,
// parser diagnostics, filesystem contents or activation authority.
type storageMDV10ObservationSummary struct {
	SchemaVersion                      int      `json:"schema_version"`
	Status                             string   `json:"status"`
	Scope                              string   `json:"scope"`
	CandidateDiskCount                 int      `json:"candidate_disk_count"`
	GPTDiskCount                       int      `json:"gpt_disk_count"`
	RAIDPartitionCount                 int      `json:"raid_partition_count"`
	CandidateComponents                int      `json:"candidate_components"`
	UnqualifiedComponents              int      `json:"unqualified_components"`
	UnidentifiedCandidateComponents    int      `json:"unidentified_candidate_components"`
	ArrayCount                         int      `json:"array_count"`
	MetadataConsistentArrayCount       int      `json:"metadata_consistent_array_count"`
	IncompleteArrayCount               int      `json:"incomplete_array_count"`
	DivergentEventArrayCount           int      `json:"divergent_event_array_count"`
	ConflictingArrayCount              int      `json:"conflicting_array_count"`
	AmbiguousArrayCount                int      `json:"ambiguous_array_count"`
	MetadataActiveRoleCoverageComplete bool     `json:"metadata_active_role_coverage_complete"`
	BlockMetadataRead                  bool     `json:"block_metadata_read"`
	MDV10SuperblocksRead               bool     `json:"md_v1_0_superblocks_read"`
	FilesystemDataRead                 bool     `json:"filesystem_data_read"`
	MountPerformed                     bool     `json:"mount_performed"`
	AssemblyPerformed                  bool     `json:"assembly_performed"`
	ImportPerformed                    bool     `json:"import_performed"`
	MutationsPerformed                 bool     `json:"mutations_performed"`
	Limitations                        []string `json:"limitations"`
}

func summarizeTrustedMDV10Observation(observation trustedMDV10Observation) (storageMDV10ObservationSummary, error) {
	comparison := observation.Comparison
	if observation.CandidateDiskCount < 1 || observation.CandidateDiskCount > storageMDV10MaximumDisks ||
		observation.GPTDiskCount != observation.CandidateDiskCount || observation.RAIDPartitionCount < 0 ||
		observation.RAIDPartitionCount > storageMDV10MaximumDisks*storageMDV10MaximumPartitions ||
		comparison.Arrays == nil || comparison.CandidateComponents > uint32(observation.RAIDPartitionCount) ||
		comparison.UnqualifiedComponents > uint32(observation.RAIDPartitionCount) ||
		comparison.CandidateComponents+comparison.UnqualifiedComponents != uint32(observation.RAIDPartitionCount) ||
		comparison.UnidentifiedCandidateComponents > comparison.CandidateComponents {
		return storageMDV10ObservationSummary{}, errStorageDiscoveryIncomplete
	}

	summary := storageMDV10ObservationSummary{
		SchemaVersion: 1, Status: "complete", Scope: "broker-read-only-md-v1.0",
		CandidateDiskCount: observation.CandidateDiskCount, GPTDiskCount: observation.GPTDiskCount,
		RAIDPartitionCount:              observation.RAIDPartitionCount,
		CandidateComponents:             int(comparison.CandidateComponents),
		UnqualifiedComponents:           int(comparison.UnqualifiedComponents),
		UnidentifiedCandidateComponents: int(comparison.UnidentifiedCandidateComponents),
		ArrayCount:                      len(comparison.Arrays), BlockMetadataRead: true,
		MDV10SuperblocksRead: observation.RAIDPartitionCount > 0,
		FilesystemDataRead:   false, MountPerformed: false, AssemblyPerformed: false,
		ImportPerformed: false, MutationsPerformed: false,
		Limitations: append([]string{}, storageMDV10ObservationLimitations[:]...),
	}
	for _, array := range comparison.Arrays {
		switch array.Status {
		case mdmetadata.ArrayMetadataConsistent:
			summary.MetadataConsistentArrayCount++
		case mdmetadata.ArrayIncomplete:
			summary.IncompleteArrayCount++
		case mdmetadata.ArrayDivergentEvents:
			summary.DivergentEventArrayCount++
		case mdmetadata.ArrayConflicting:
			summary.ConflictingArrayCount++
		case mdmetadata.ArrayAmbiguous:
			summary.AmbiguousArrayCount++
		default:
			return storageMDV10ObservationSummary{}, errStorageDiscoveryIncomplete
		}
	}
	summary.MetadataActiveRoleCoverageComplete = summary.ArrayCount > 0 &&
		summary.CandidateComponents > 0 && summary.UnqualifiedComponents == 0 &&
		summary.UnidentifiedCandidateComponents == 0 &&
		summary.MetadataConsistentArrayCount == summary.ArrayCount
	if !validStorageMDV10ObservationSummary(summary) {
		return storageMDV10ObservationSummary{}, errStorageDiscoveryIncomplete
	}
	return summary, nil
}

func validStorageMDV10ObservationSummary(summary storageMDV10ObservationSummary) bool {
	if summary.SchemaVersion != 1 || summary.Status != "complete" || summary.Scope != "broker-read-only-md-v1.0" ||
		summary.CandidateDiskCount < 1 || summary.CandidateDiskCount > storageMDV10MaximumDisks ||
		summary.GPTDiskCount != summary.CandidateDiskCount ||
		summary.RAIDPartitionCount < 0 || summary.RAIDPartitionCount > storageMDV10MaximumDisks*storageMDV10MaximumPartitions ||
		summary.CandidateComponents < 0 || summary.UnqualifiedComponents < 0 ||
		summary.CandidateComponents+summary.UnqualifiedComponents != summary.RAIDPartitionCount ||
		summary.UnidentifiedCandidateComponents < 0 || summary.UnidentifiedCandidateComponents > summary.CandidateComponents ||
		summary.ArrayCount < 0 || summary.ArrayCount > summary.CandidateComponents ||
		summary.MetadataConsistentArrayCount < 0 || summary.IncompleteArrayCount < 0 ||
		summary.DivergentEventArrayCount < 0 || summary.ConflictingArrayCount < 0 || summary.AmbiguousArrayCount < 0 ||
		summary.MetadataConsistentArrayCount+summary.IncompleteArrayCount+summary.DivergentEventArrayCount+
			summary.ConflictingArrayCount+summary.AmbiguousArrayCount != summary.ArrayCount ||
		!summary.BlockMetadataRead || summary.MDV10SuperblocksRead != (summary.RAIDPartitionCount > 0) ||
		summary.FilesystemDataRead || summary.MountPerformed || summary.AssemblyPerformed ||
		summary.ImportPerformed || summary.MutationsPerformed || summary.Limitations == nil ||
		len(summary.Limitations) != len(storageMDV10ObservationLimitations) {
		return false
	}
	wantCoverage := summary.ArrayCount > 0 && summary.CandidateComponents > 0 &&
		summary.UnqualifiedComponents == 0 && summary.UnidentifiedCandidateComponents == 0 &&
		summary.MetadataConsistentArrayCount == summary.ArrayCount
	if summary.MetadataActiveRoleCoverageComplete != wantCoverage {
		return false
	}
	for index, limitation := range summary.Limitations {
		if limitation == "" || len(limitation) > 512 || limitation != storageMDV10ObservationLimitations[index] {
			return false
		}
	}
	return true
}

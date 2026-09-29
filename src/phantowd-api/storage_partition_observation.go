// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

const (
	// The disposable QEMU broker fixture includes six SCSI devices; real EX4
	// hardware has four bays. Never truncate a larger complete candidate set.
	storageGPTObservationMaxDisks = 6
	storageGPTObservationPath     = "/api/v1/storage/gpt-observation"
)

var storageGPTObservationLimitations = [...]string{
	"only first-sector partition metadata and, for valid GPT candidates, GPT headers and entry metadata were read; filesystem signatures, partition contents and file data were not probed",
	"coverage and duplicate counts apply only to this complete eligible candidate set at one point in time; they do not establish global identity, WD compatibility, health or bay mapping",
	"only GPT candidates contribute identity; MBR/DOS, other partition schemes and candidates without a valid GPT table remain unsupported coverage gaps",
	"cancellation cannot guarantee prompt recovery from uninterruptible kernel block I/O; this is not EX4 hardware qualification",
	"no assembly, mount, import, repair, write or other storage mutation was performed",
}

// storageGPTObservationSummary is the only partition-observation result that
// may cross from the storage broker into the HTTP process. Raw disk GUIDs,
// PARTUUIDs, partition geometry, kernel names and paths are deliberately absent.
type storageGPTObservationSummary struct {
	SchemaVersion              int      `json:"schema_version"`
	Status                     string   `json:"status"`
	Scope                      string   `json:"scope"`
	EligibleCandidateCount     int      `json:"eligible_candidate_count"`
	GPTDiskCount               int      `json:"gpt_disk_count"`
	PartitionCount             int      `json:"partition_count"`
	UnsupportedTableCount      int      `json:"unsupported_or_non_gpt_count"`
	Coverage                   string   `json:"gpt_coverage"`
	AmbiguousDiskGUIDCount     int      `json:"ambiguous_disk_guid_count"`
	AmbiguousPARTUUIDCount     int      `json:"ambiguous_partuuid_count"`
	IdentityEvidenceIncomplete bool     `json:"identity_evidence_incomplete"`
	ContentRead                bool     `json:"content_read"`
	MountPerformed             bool     `json:"mount_performed"`
	AssemblyPerformed          bool     `json:"assembly_performed"`
	ImportPerformed            bool     `json:"import_performed"`
	MutationsPerformed         bool     `json:"mutations_performed"`
	Limitations                []string `json:"limitations"`
}

func summarizeGPTIdentityObservation(observation gptIdentitySetObservation) (storageGPTObservationSummary, error) {
	if observation.CandidateCount < 0 || observation.CandidateCount > storageGPTObservationMaxDisks ||
		observation.GPTDiskCount < 0 || observation.GPTDiskCount > observation.CandidateCount ||
		observation.Bindings == nil || len(observation.Bindings) != observation.CandidateCount {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	summary := storageGPTObservationSummary{
		SchemaVersion: 1, Status: "complete", Scope: "manual-gpt-metadata-read-only",
		EligibleCandidateCount: observation.CandidateCount, GPTDiskCount: observation.GPTDiskCount,
		UnsupportedTableCount:      observation.UnsupportedTableCount + observation.NoTableCount,
		IdentityEvidenceIncomplete: observation.VPDIdentityEvidenceIncomplete,
		ContentRead:                false, MountPerformed: false, AssemblyPerformed: false,
		ImportPerformed: false, MutationsPerformed: false,
		Limitations: append([]string{}, storageGPTObservationLimitations[:]...),
	}
	for _, binding := range observation.Bindings {
		if binding.TableDisposition == partitionTableGPT {
			if binding.TableIDStatus == gptIdentityAmbiguousObserved {
				summary.AmbiguousDiskGUIDCount++
			}
			for _, partition := range binding.Partitions {
				summary.PartitionCount++
				if partition.UUIDStatus == gptIdentityAmbiguousObserved {
					summary.AmbiguousPARTUUIDCount++
				}
			}
		}
	}
	summary.Coverage = observation.Coverage
	if !validStorageGPTObservationSummary(summary) {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	return summary, nil
}

func validStorageGPTObservationSummary(summary storageGPTObservationSummary) bool {
	if summary.SchemaVersion != 1 || summary.Status != "complete" || summary.Scope != "manual-gpt-metadata-read-only" ||
		summary.EligibleCandidateCount < 0 || summary.EligibleCandidateCount > storageGPTObservationMaxDisks ||
		summary.GPTDiskCount < 0 || summary.GPTDiskCount > summary.EligibleCandidateCount ||
		summary.PartitionCount < 0 || summary.PartitionCount > storageGPTObservationMaxDisks*256 ||
		summary.UnsupportedTableCount != summary.EligibleCandidateCount-summary.GPTDiskCount ||
		summary.AmbiguousDiskGUIDCount < 0 || summary.AmbiguousDiskGUIDCount > summary.GPTDiskCount ||
		summary.AmbiguousPARTUUIDCount < 0 || summary.AmbiguousPARTUUIDCount > summary.PartitionCount ||
		summary.ContentRead || summary.MountPerformed || summary.AssemblyPerformed || summary.ImportPerformed ||
		summary.MutationsPerformed || summary.Limitations == nil || len(summary.Limitations) != 5 {
		return false
	}
	wantCoverage := gptIdentityCoverageNone
	switch {
	case summary.EligibleCandidateCount == 0:
		wantCoverage = gptIdentityCoverageEmpty
	case summary.GPTDiskCount == 0:
		wantCoverage = gptIdentityCoverageNone
	case summary.GPTDiskCount == summary.EligibleCandidateCount:
		wantCoverage = gptIdentityCoverageAllCandidates
	default:
		wantCoverage = gptIdentityCoveragePartial
	}
	if summary.Coverage != wantCoverage {
		return false
	}
	for index, limitation := range summary.Limitations {
		if limitation == "" || len(limitation) > 512 || limitation != storageGPTObservationLimitations[index] {
			return false
		}
	}
	return true
}

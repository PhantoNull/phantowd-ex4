// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestStorageGPTSummaryCountsDuplicatesButNeverSerializesIdentifiers(t *testing.T) {
	const diskGUID = "12345678-1234-4234-8234-123456789abc"
	const partUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	const typeGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
	bindings := []diskPartitionBinding{
		{DiskName: "sda", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 0, DiskSequence: 101},
			Scheme: "gpt", TableID: diskGUID, TableIDStatus: gptIdentityAmbiguousObserved,
			TableDisposition: partitionTableGPT, Partitions: []kernelPartitionBinding{{KernelName: "sda1", Major: 8,
				Minor: 1, Number: 1, Start512B: 2048, Size512B: 1024, UUID: partUUID,
				UUIDStatus: gptIdentityAmbiguousObserved, TypeGUID: typeGUID, TypeHint: gptTypeHintLinuxData}}},
		{DiskName: "sdb", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 102},
			Scheme: "gpt", TableID: diskGUID, TableIDStatus: gptIdentityAmbiguousObserved,
			TableDisposition: partitionTableGPT, Partitions: []kernelPartitionBinding{{KernelName: "sdb1", Major: 8,
				Minor: 17, Number: 1, Start512B: 2048, Size512B: 1024, UUID: partUUID,
				UUIDStatus: gptIdentityAmbiguousObserved, TypeGUID: typeGUID, TypeHint: gptTypeHintLinuxData}}},
	}
	observation, err := classifyGPTPartitionIdentities(bindings)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := summarizeGPTIdentityObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EligibleCandidateCount != 2 || summary.GPTDiskCount != 2 || summary.PartitionCount != 2 ||
		summary.AmbiguousDiskGUIDCount != 2 || summary.AmbiguousPARTUUIDCount != 2 ||
		summary.Coverage != gptIdentityCoverageAllCandidates || summary.ContentRead || summary.MountPerformed ||
		summary.AssemblyPerformed || summary.ImportPerformed || summary.MutationsPerformed {
		t.Fatalf("incorrect redacted summary: %+v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{diskGUID, partUUID, typeGUID, "sda", "sdb", "TableID", "TypeGUID"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("summary exposed private observation value %q: %s", private, encoded)
		}
	}
}

func TestStorageGPTSummaryFailsClosedForUnsupportedAndInvalidObservations(t *testing.T) {
	unsupported, err := summarizeGPTIdentityObservation(gptIdentitySetObservation{
		CandidateCount: 2, UnsupportedTableCount: 1, NoTableCount: 1, Coverage: gptIdentityCoverageNone,
		Bindings: []diskPartitionBinding{
			{TableDisposition: partitionTableUnsupported, Partitions: []kernelPartitionBinding{}},
			{TableDisposition: partitionTableNoTable, Partitions: []kernelPartitionBinding{}},
		},
	})
	if err != nil || unsupported.UnsupportedTableCount != 2 || unsupported.GPTDiskCount != 0 || unsupported.PartitionCount != 0 {
		t.Fatalf("unsupported table was not safely summarized: %+v %v", unsupported, err)
	}
	invalid := unsupported
	invalid.Limitations = append([]string{}, unsupported.Limitations...)
	invalid.Limitations[0] = "private PARTUUID 12345678-1234-4234-8234-123456789abc"
	if validStorageGPTObservationSummary(invalid) {
		t.Fatal("unexpected text was accepted in redacted broker limitations")
	}
	invalid = unsupported
	invalid.ContentRead = true
	if validStorageGPTObservationSummary(invalid) {
		t.Fatal("content-read claim was accepted")
	}
}

func TestStorageGPTSummaryKeepsCompleteSixDeviceQEMUFixtureBounded(t *testing.T) {
	bindings := make([]diskPartitionBinding, storageGPTObservationMaxDisks)
	for index := range bindings {
		bindings[index].TableDisposition = partitionTableUnsupported
		bindings[index].Partitions = []kernelPartitionBinding{}
	}
	observation := gptIdentitySetObservation{
		CandidateCount: len(bindings), UnsupportedTableCount: len(bindings),
		Coverage: gptIdentityCoverageNone, Bindings: bindings,
	}
	summary, err := summarizeGPTIdentityObservation(observation)
	if err != nil || summary.EligibleCandidateCount != 6 || summary.UnsupportedTableCount != 6 {
		t.Fatalf("complete six-device fixture was not safely summarized: %+v %v", summary, err)
	}
	if validStorageGPTObservationSummary(storageGPTObservationSummary{
		SchemaVersion: 1, Status: "complete", Scope: "manual-gpt-metadata-read-only",
		EligibleCandidateCount: 7, Coverage: gptIdentityCoverageNone,
		UnsupportedTableCount: 7, Limitations: append([]string{}, storageGPTObservationLimitations[:]...),
	}) {
		t.Fatal("candidate count beyond the complete-set bound was accepted")
	}
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestTrustedMDV10ObservationReadsOnlyCorrelatedLinuxRAIDPartitions(t *testing.T) {
	discovery, identities := trustedMDV10Fixture(t)
	defer discovery.Close()
	var observed []string

	result, err := inspectTrustedMDV10Candidates(context.Background(), discovery, identities,
		func(_ *os.File, generation volumeprobe.BlockDeviceGeneration, _ uint64, partition mdmetadata.Partition) (mdmetadata.Observation, error) {
			observed = append(observed, generationName(generation)+":"+string(rune('0'+partition.Number)))
			return mdV10Observation(partition.Number, int(generation.Minor/16)-1), nil
		})
	if err != nil {
		t.Fatalf("inspect trusted MD candidates: %v", err)
	}
	if result.CandidateDiskCount != 2 || result.GPTDiskCount != 2 || result.RAIDPartitionCount != 2 ||
		result.Comparison.CandidateComponents != 2 || result.Comparison.UnqualifiedComponents != 0 ||
		len(result.Comparison.Arrays) != 1 || result.Comparison.Arrays[0].Status != mdmetadata.ArrayMetadataConsistent ||
		result.Comparison.Arrays[0].ObservedActiveRoles != 2 {
		t.Fatalf("incomplete trusted MD observation: %+v", result)
	}
	if !reflect.DeepEqual(observed, []string{"sdb:1", "sdc:1"}) {
		t.Fatalf("inspected partitions %v; expected only GPT-declared Linux RAID members", observed)
	}
}

func TestTrustedMDV10ObservationRefusesIncompleteGPTCoverageBeforeReading(t *testing.T) {
	discovery, identities := trustedMDV10Fixture(t)
	defer discovery.Close()
	identities.GPTDiskCount = 1
	identities.Coverage = gptIdentityCoveragePartial
	called := false

	_, err := inspectTrustedMDV10Candidates(context.Background(), discovery, identities,
		func(*os.File, volumeprobe.BlockDeviceGeneration, uint64, mdmetadata.Partition) (mdmetadata.Observation, error) {
			called = true
			return mdmetadata.Observation{}, nil
		})
	if err == nil || called {
		t.Fatalf("incomplete partition-table coverage was accepted: err=%v inspector_called=%v", err, called)
	}
}

func trustedMDV10Fixture(t *testing.T) (*trustedStorageDiscovery, gptIdentitySetObservation) {
	t.Helper()
	root := t.TempDir()
	names := []string{"sdb", "sdc"}
	discovery := &trustedStorageDiscovery{
		inventory: storageSnapshot{
			SchemaVersion: 2, Scope: "kernel-sysfs-only", InventoryReadOnly: true,
			DeviceCount: 2, Limitations: []string{"synthetic trusted inventory"}, collectionComplete: true,
			Observations: []blockObservation{
				{Name: "sdb", Kind: "block", Major: 8, Minor: 16, SizeBytes: 32 * 1024 * 1024, diskSequence: 11},
				{Name: "sdc", Kind: "block", Major: 8, Minor: 32, SizeBytes: 32 * 1024 * 1024, diskSequence: 12},
			},
		},
		candidates: []storageDiscoveryCandidate{
			{Name: "sdb", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 11}},
			{Name: "sdc", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 32, DiskSequence: 12}},
		},
	}
	for index, name := range names {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("read-only fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		discovery.sources = append(discovery.sources, volumeprobe.BlockDeviceSource{
			File: file, Generation: discovery.candidates[index].Generation,
		})
	}
	identities := gptIdentitySetObservation{
		CandidateCount: 2, GPTDiskCount: 2, Coverage: gptIdentityCoverageAllCandidates,
		Bindings: []diskPartitionBinding{
			mdV10GPTBinding("sdb", discovery.candidates[0].Generation, 1),
			mdV10GPTBinding("sdc", discovery.candidates[1].Generation, 2),
		},
	}
	return discovery, identities
}

func mdV10GPTBinding(name string, generation volumeprobe.BlockDeviceGeneration, member uint32) diskPartitionBinding {
	return diskPartitionBinding{
		DiskName: name, Generation: generation, SourceStatus: "other-signature",
		TableDisposition: partitionTableGPT, Scheme: "gpt",
		TableID:       strings.Repeat("1", 8) + "-1111-4111-8111-11111111111" + string(rune('0'+member)),
		TableIDStatus: gptIdentitySingletonObserved,
		Partitions: []kernelPartitionBinding{
			{KernelName: name + "1", Major: 8, Minor: generation.Minor + 1, Number: 1,
				Start512B: 2048, Size512B: 63455, TypeGUID: "a19d880f-05fc-4d3b-a006-743f0f84911e",
				TypeHint: gptTypeHintLinuxRAID, UUID: strings.Repeat("2", 8) + "-2222-4222-8222-22222222222" + string(rune('0'+member)),
				UUIDStatus: gptIdentitySingletonObserved},
			{name + "2", 8, generation.Minor + 2, 2, 65503, 32, "0fc63daf-8483-4772-8e79-3d69d8477de4",
				gptTypeHintLinuxData, strings.Repeat("3", 8) + "-3333-4333-8333-33333333333" + string(rune('0'+member)),
				gptIdentitySingletonObserved},
		},
	}
}

func mdV10Observation(partitionNumber uint32, member int) mdmetadata.Observation {
	return mdmetadata.Observation{
		Status: mdmetadata.StatusCandidate, MetadataVersion: "1.0", MetadataRead: true,
		PartitionNumber: partitionNumber, PartitionFirstLBA: 2048, PartitionLastLBA: 65502, DiskSectors: 65536,
		PartitionBytes: 63455 * 512, SuperblockChecksumStatus: "valid", FeatureMap: 0,
		ArrayLevel: 1, ArraySizeSectors: 63000, RAIDDisks: 2, MaxDevices: 2,
		MemberNumber: uint32(member), MemberRole: uint16(member), MemberRoleDescription: "active-slot",
		ComponentDataSectors:      62000,
		ArrayIdentityFingerprint:  strings.Repeat("a", 64),
		MemberIdentityFingerprint: strings.Repeat(string(rune('b'+member)), 64),
	}
}

func generationName(generation volumeprobe.BlockDeviceGeneration) string {
	if generation.Minor == 16 {
		return "sdb"
	}
	return "sdc"
}

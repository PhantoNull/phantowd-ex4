//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestTrustedMDV10CoordinatorRejectsStateChangeBeforeMetadataReads(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS, fstest.MapFS)
	}{
		{
			name: "storage generation changed",
			mutate: func(sysfs fstest.MapFS, _ fstest.MapFS) {
				sysfs["devices/pci0000:00/block/sdb/diskseq"] = &fstest.MapFile{Data: []byte("999\n")}
			},
		},
		{
			name: "mount inventory changed",
			mutate: func(_ fstest.MapFS, proc fstest.MapFS) {
				proc["self/mountinfo"] = &fstest.MapFile{Data: []byte(
					"36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n" +
						"37 36 8:16 / /candidate rw,relatime - ext4 /dev/sdb rw\n")}
			},
		},
		{
			name: "active swap appeared",
			mutate: func(_ fstest.MapFS, proc fstest.MapFS) {
				proc["swaps"] = &fstest.MapFile{Data: []byte(emptySwaps + "/swapfile file 1024 0 -2\n")}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sysfs, proc, open, opened := trustedMDV10CoordinatorFixture(t)
			var inspectCalls int
			observeGPT := func(_ context.Context, sources []volumeprobe.BlockDeviceSource) ([]volumeprobe.Result, error) {
				if len(sources) != 2 {
					t.Fatalf("GPT observer received %d sources; want the complete two-disk set", len(sources))
				}
				results := trustedMDV10GPTResults()
				test.mutate(sysfs, proc)
				return results, nil
			}
			inspect := func(*os.File, volumeprobe.BlockDeviceGeneration, uint64, mdmetadata.Partition) (mdmetadata.Observation, error) {
				inspectCalls++
				return mdV10Observation(1, inspectCalls-1), nil
			}

			got, err := observeTrustedMDV10WithObservers(context.Background(), sysfs, proc, open, observeGPT, inspect)
			if !errors.Is(err, errStorageDiscoveryIncomplete) || !reflect.DeepEqual(got, trustedMDV10Observation{}) {
				t.Fatalf("changed pre-read state produced an observation: %+v, %v", got, err)
			}
			if inspectCalls != 0 {
				t.Fatalf("metadata parser ran %d times after the pre-read recheck failed", inspectCalls)
			}
			assertMDV10SourcesClosed(t, opened)
		})
	}
}

func TestTrustedMDV10CoordinatorDiscardsResultIfStateChangesDuringReads(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS, fstest.MapFS)
	}{
		{
			name: "storage generation changed",
			mutate: func(sysfs fstest.MapFS, _ fstest.MapFS) {
				sysfs["devices/pci0000:00/block/sdb/diskseq"] = &fstest.MapFile{Data: []byte("999\n")}
			},
		},
		{
			name: "mount inventory changed",
			mutate: func(_ fstest.MapFS, proc fstest.MapFS) {
				proc["self/mountinfo"] = &fstest.MapFile{Data: []byte(
					"36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n" +
						"37 36 8:16 / /candidate rw,relatime - ext4 /dev/sdb rw\n")}
			},
		},
		{
			name: "active swap appeared",
			mutate: func(_ fstest.MapFS, proc fstest.MapFS) {
				proc["swaps"] = &fstest.MapFile{Data: []byte(emptySwaps + "/swapfile file 1024 0 -2\n")}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sysfs, proc, open, opened := trustedMDV10CoordinatorFixture(t)
			var inspectCalls int
			observeGPT := func(_ context.Context, _ []volumeprobe.BlockDeviceSource) ([]volumeprobe.Result, error) {
				return trustedMDV10GPTResults(), nil
			}
			inspect := func(_ *os.File, generation volumeprobe.BlockDeviceGeneration, _ uint64, partition mdmetadata.Partition) (mdmetadata.Observation, error) {
				inspectCalls++
				if inspectCalls == 1 {
					test.mutate(sysfs, proc)
				}
				return mdV10Observation(partition.Number, int(generation.Minor/16)-1), nil
			}

			got, err := observeTrustedMDV10WithObservers(context.Background(), sysfs, proc, open, observeGPT, inspect)
			if !errors.Is(err, errStorageDiscoveryIncomplete) || !reflect.DeepEqual(got, trustedMDV10Observation{}) {
				t.Fatalf("changed post-read state escaped as an observation: %+v, %v", got, err)
			}
			if inspectCalls != 2 {
				t.Fatalf("fixture should parse both members before the final set recheck, parsed %d", inspectCalls)
			}
			assertMDV10SourcesClosed(t, opened)
		})
	}
}

func TestTrustedMDV10CoordinatorRejectsIncompleteGPTSetBeforeMetadataReads(t *testing.T) {
	sysfs, proc, open, opened := trustedMDV10CoordinatorFixture(t)
	inspectCalled := false
	observeGPT := func(_ context.Context, _ []volumeprobe.BlockDeviceSource) ([]volumeprobe.Result, error) {
		return trustedMDV10GPTResults()[:1], nil
	}
	inspect := func(*os.File, volumeprobe.BlockDeviceGeneration, uint64, mdmetadata.Partition) (mdmetadata.Observation, error) {
		inspectCalled = true
		return mdmetadata.Observation{}, nil
	}

	got, err := observeTrustedMDV10WithObservers(context.Background(), sysfs, proc, open, observeGPT, inspect)
	if !errors.Is(err, errStorageDiscoveryIncomplete) || !reflect.DeepEqual(got, trustedMDV10Observation{}) {
		t.Fatalf("partial GPT result set was accepted: %+v, %v", got, err)
	}
	if inspectCalled {
		t.Fatal("MD parser ran with incomplete GPT coverage")
	}
	assertMDV10SourcesClosed(t, opened)
}

func trustedMDV10CoordinatorFixture(
	t *testing.T,
) (fstest.MapFS, fstest.MapFS, storageSourceOpener, *mdV10OpenedSources) {
	t.Helper()
	sysfs := fixtureDiscoverySysfs()
	addDiscoveryGPTPartition(sysfs, "sdb", 8, 17)
	addDiscoveryGPTPartition(sysfs, "sdc", 8, 33)
	sysfs["devices/pci0000:00/block/sdb/size"] = &fstest.MapFile{Data: []byte("65536\n")}
	sysfs["devices/pci0000:00/block/sdc/size"] = &fstest.MapFile{Data: []byte("65536\n")}
	proc := discoveryProc("36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n", emptySwaps)
	directory := t.TempDir()
	opened := &mdV10OpenedSources{files: make([]*os.File, 0, 2)}
	open := func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		sources := make([]volumeprobe.BlockDeviceSource, 0, len(devices))
		for _, device := range devices {
			path := filepath.Join(directory, device.Name)
			if err := os.WriteFile(path, []byte("synthetic read-only source"), 0600); err != nil {
				return sources, err
			}
			file, err := os.Open(path)
			if err != nil {
				return sources, err
			}
			opened.files = append(opened.files, file)
			sources = append(sources, volumeprobe.BlockDeviceSource{File: file, Generation: device.Generation})
		}
		return sources, nil
	}
	return sysfs, proc, open, opened
}

func trustedMDV10GPTResults() []volumeprobe.Result {
	return []volumeprobe.Result{
		trustedMDV10GPTResult("500f0000-0000-0000-0000-000000000102", "8fd20a43-e550-4632-9a8e-5241c40c0861"),
		trustedMDV10GPTResult("500f0000-0000-0000-0000-000000000103", "8fd20a43-e550-4632-9a8e-5241c40c0862"),
	}
}

func trustedMDV10GPTResult(tableID, partitionUUID string) volumeprobe.Result {
	return volumeprobe.Result{
		Status: "other-signature", SourceKind: "block-device",
		PartitionTable: &volumeprobe.PartitionTable{
			Scheme: "gpt", ID: tableID,
			Partitions: []volumeprobe.Partition{{
				Number: 1, Start512B: 2048, Size512B: 63455, UUID: partitionUUID,
				TypeID: "a19d880f-05fc-4d3b-a006-743f0f84911e",
			}},
		},
	}
}

type mdV10OpenedSources struct {
	files []*os.File
}

func assertMDV10SourcesClosed(t *testing.T, opened *mdV10OpenedSources) {
	t.Helper()
	for _, source := range opened.files {
		if _, err := source.Stat(); err == nil {
			t.Fatal("trusted MD coordinator left a source descriptor open after refusal")
		}
	}
}

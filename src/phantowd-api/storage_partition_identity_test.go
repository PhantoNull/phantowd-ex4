// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"os"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestCorrelateDiskGPTPartitionsWithCompleteKernelChildren(t *testing.T) {
	storage, err := collectStorage(fixtureSysfs())
	if err != nil {
		t.Fatal(err)
	}
	result := volumeprobe.Result{
		Status: "other-signature", SourceKind: "block-device",
		PartitionTable: &volumeprobe.PartitionTable{
			Scheme: "gpt", ID: "fedcba98-7654-3210-fedc-ba9876543210",
			Partitions: []volumeprobe.Partition{{
				Number: 1, Start512B: 34, Size512B: 2097118,
				UUID:   "00112233-4455-6677-8899-aabbccddeeff",
				TypeID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
			}},
		},
	}

	matched, err := correlateDiskPartitionTable(storage.Observations[0], storage.Observations, result)
	if err != nil {
		t.Fatalf("complete disk table and sysfs partition set should correlate: %v", err)
	}
	if matched.DiskName != "sda" || matched.TableDisposition != partitionTableGPT || matched.Scheme != "gpt" ||
		matched.TableID != "fedcba98-7654-3210-fedc-ba9876543210" ||
		len(matched.Partitions) != 1 || matched.Partitions[0].KernelName != "sda1" ||
		matched.Partitions[0].Start512B != 34 || matched.Partitions[0].Size512B != 2097118 ||
		matched.Partitions[0].UUID != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("disk/table/kernel partition binding is incomplete: %+v", matched)
	}
	encoded, err := json.Marshal(matched)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("private disk/partition observations must not serialize to JSON: %s (err=%v)", encoded, err)
	}

	t.Run("DOS table is unsupported and identifiers are discarded", func(t *testing.T) {
		dos := volumeprobe.Result{
			Status: "other-signature", SourceKind: "block-device",
			PartitionTable: &volumeprobe.PartitionTable{
				Scheme: "dos", ID: "1234abcd",
				Partitions: []volumeprobe.Partition{{
					Number: 1, Start512B: 34, Size512B: 2097118,
					UUID: "1234abcd-01", TypeID: "0x83",
				}},
			},
		}
		observed, err := correlateDiskPartitionTable(storage.Observations[0], storage.Observations, dos)
		if err != nil {
			t.Fatalf("valid DOS table should be reported as unsupported: %v", err)
		}
		if observed.TableDisposition != partitionTableUnsupported || observed.Scheme != "" ||
			observed.TableID != "" || len(observed.Partitions) != 0 {
			t.Fatalf("unsupported DOS identifiers escaped into the private binding: %+v", observed)
		}
		encoded, err := json.Marshal(observed)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("unsupported DOS observation must not serialize to JSON: %s (err=%v)", encoded, err)
		}
	})

	t.Run("sysfs start mismatch refuses", func(t *testing.T) {
		mismatched := storage.Observations[1]
		mismatched.partitionStart512B++
		inventory := append([]blockObservation(nil), storage.Observations...)
		inventory[1] = mismatched
		if _, err := correlateDiskPartitionTable(inventory[0], inventory, result); err == nil {
			t.Fatal("kernel partition at another start was accepted")
		}
	})

	t.Run("missing sysfs child refuses", func(t *testing.T) {
		withoutPartition, err := collectStorage(sysfsWithoutPartition(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := correlateDiskPartitionTable(withoutPartition.Observations[0], withoutPartition.Observations, result); err == nil {
			t.Fatal("partition-table entry absent from kernel inventory was accepted")
		}
	})

	t.Run("partition without table refuses", func(t *testing.T) {
		noTable := volumeprobe.Result{Status: "unidentified", SourceKind: "block-device"}
		if _, err := correlateDiskPartitionTable(storage.Observations[0], storage.Observations, noTable); err == nil {
			t.Fatal("kernel partitions without a recognized complete table were accepted")
		}
	})

	t.Run("table with extra entry refuses", func(t *testing.T) {
		extra := result
		extra.PartitionTable = &volumeprobe.PartitionTable{
			Scheme: result.PartitionTable.Scheme, ID: result.PartitionTable.ID,
			Partitions: append(append([]volumeprobe.Partition(nil), result.PartitionTable.Partitions...),
				volumeprobe.Partition{Number: 2, Start512B: 2097150, Size512B: 1,
					UUID:   "10112233-4455-6677-8899-aabbccddeeff",
					TypeID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"}),
		}
		if _, err := correlateDiskPartitionTable(storage.Observations[0], storage.Observations, extra); err == nil {
			t.Fatal("parser table entry missing from the complete sysfs children was accepted")
		}
	})

	t.Run("partition size mismatch refuses", func(t *testing.T) {
		mismatched := storage.Observations[1]
		mismatched.SizeBytes -= 512
		inventory := append([]blockObservation(nil), storage.Observations...)
		inventory[1] = mismatched
		if _, err := correlateDiskPartitionTable(inventory[0], inventory, result); err == nil {
			t.Fatal("kernel partition with another size was accepted")
		}
	})
}

func TestCorrelateCandidatePartitionTablesRequiresCompleteGenerationBoundSet(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	proc := discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", emptySwaps)
	discovery, err := discoverTrustedStorageWith(sysfs, proc, func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		sources := make([]volumeprobe.BlockDeviceSource, 0, len(devices))
		for range devices {
			file, err := os.CreateTemp(t.TempDir(), "partition-correlation-source-")
			if err != nil {
				return sources, err
			}
			sources = append(sources, volumeprobe.BlockDeviceSource{File: file})
		}
		for index := range sources {
			sources[index].Generation = devices[index].Generation
		}
		return sources, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	if len(discovery.candidates) != 2 {
		t.Fatalf("fixture expected exactly two complete candidates: %+v", discovery.candidates)
	}
	current, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	results := []volumeprobe.Result{
		{Status: "ext-metadata", SourceKind: "block-device", Filesystem: "ext2", FilesystemUUID: "00112233-4455-6677-8899-aabbccddeeff"},
		{Status: "unidentified", SourceKind: "block-device"},
	}
	bindings, err := correlateCandidatePartitionTables(discovery, current, results)
	if err != nil || len(bindings) != len(discovery.candidates) {
		t.Fatalf("complete generation-bound candidate result set was rejected: bindings=%+v err=%v", bindings, err)
	}
	if _, err := correlateCandidatePartitionTables(discovery, current, results[:1]); err == nil {
		t.Fatal("partial parser-result set was accepted")
	}
	changedInventory := current
	changedInventory.Observations = append([]blockObservation(nil), current.Observations...)
	changedInventory.Observations[1].SizeBytes++
	if _, err := correlateCandidatePartitionTables(discovery, changedInventory, results); err == nil {
		t.Fatal("changed sysfs inventory was accepted for parser correlation")
	}
	changedDiscovery := *discovery
	changedDiscovery.sources = append([]volumeprobe.BlockDeviceSource(nil), discovery.sources...)
	changedDiscovery.sources[0].Generation.DiskSequence++
	if _, err := correlateCandidatePartitionTables(&changedDiscovery, current, results); err == nil {
		t.Fatal("stale source generation was accepted for parser correlation")
	}
	changedDiscovery = *discovery
	changedDiscovery.candidates = append([]storageDiscoveryCandidate(nil), discovery.candidates[:1]...)
	changedDiscovery.sources = append([]volumeprobe.BlockDeviceSource(nil), discovery.sources[:1]...)
	if _, err := correlateCandidatePartitionTables(&changedDiscovery, current, results[:1]); err == nil {
		t.Fatal("caller-selected subset was accepted as the complete candidate set")
	}
}

func sysfsWithoutPartition(t *testing.T) fstest.MapFS {
	t.Helper()
	sysfs := fixtureSysfs()
	delete(sysfs, "class/block/sda1")
	for name := range sysfs {
		if name == "devices/virtual/block/sda/sda1" ||
			len(name) > len("devices/virtual/block/sda/sda1/") &&
				name[:len("devices/virtual/block/sda/sda1/")] == "devices/virtual/block/sda/sda1/" {
			delete(sysfs, name)
		}
	}
	return sysfs
}

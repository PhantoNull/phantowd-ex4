// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestGPTIdentityClassificationMarksClonedGUIDsAmbiguousWithinObservedSet(t *testing.T) {
	bindings := []diskPartitionBinding{
		gptBindingFixture("sda", 8, 0, 11,
			"fedcba98-7654-3210-fedc-ba9876543210", "00112233-4455-6677-8899-aabbccddeeff"),
		gptBindingFixture("sdb", 8, 16, 12,
			"fedcba98-7654-3210-fedc-ba9876543210", "00112233-4455-6677-8899-aabbccddeeff"),
	}

	observed, err := classifyGPTPartitionIdentities(bindings)
	if err != nil {
		t.Fatalf("complete observed GPT set should classify: %v", err)
	}
	if observed.CandidateCount != 2 || observed.GPTDiskCount != 2 ||
		observed.Coverage != gptIdentityCoverageAllCandidates ||
		len(observed.Bindings) != 2 {
		t.Fatalf("classification lost complete GPT-set coverage: %+v", observed)
	}
	for index, binding := range observed.Bindings {
		if binding.TableIDStatus != gptIdentityAmbiguousObserved || len(binding.Partitions) != 1 ||
			binding.Partitions[0].UUIDStatus != gptIdentityAmbiguousObserved {
			t.Fatalf("cloned GPT identifiers were not marked ambiguous at index %d: %+v", index, binding)
		}
	}
	encoded, err := json.Marshal(observed)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("GPT collision observations must remain private: %s (err=%v)", encoded, err)
	}
}

func TestGPTIdentityClassificationSeparatesDiskAndPartitionCollisions(t *testing.T) {
	for _, test := range []struct {
		name                string
		secondDiskGUID      string
		secondPartUUID      string
		expectDiskAmbiguous bool
		expectPartAmbiguous bool
	}{
		{
			name: "duplicate disk GUID only", secondDiskGUID: "fedcba98-7654-3210-fedc-ba9876543210",
			secondPartUUID:      "10112233-4455-6677-8899-aabbccddeeff",
			expectDiskAmbiguous: true,
		},
		{
			name: "duplicate PARTUUID only", secondDiskGUID: "00112233-7654-3210-fedc-ba9876543210",
			secondPartUUID:      "00112233-4455-6677-8899-aabbccddeeff",
			expectPartAmbiguous: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindings := []diskPartitionBinding{
				gptBindingFixture("sda", 8, 0, 11,
					"fedcba98-7654-3210-fedc-ba9876543210", "00112233-4455-6677-8899-aabbccddeeff"),
				gptBindingFixture("sdb", 8, 16, 12, test.secondDiskGUID, test.secondPartUUID),
			}
			observed, err := classifyGPTPartitionIdentities(bindings)
			if err != nil {
				t.Fatalf("two complete GPT observations should classify: %v", err)
			}
			wantDiskStatus := gptIdentitySingletonObserved
			if test.expectDiskAmbiguous {
				wantDiskStatus = gptIdentityAmbiguousObserved
			}
			wantPartStatus := gptIdentitySingletonObserved
			if test.expectPartAmbiguous {
				wantPartStatus = gptIdentityAmbiguousObserved
			}
			for _, binding := range observed.Bindings {
				if binding.TableIDStatus != wantDiskStatus || binding.Partitions[0].UUIDStatus != wantPartStatus {
					t.Fatalf("disk and partition collisions were conflated: %+v", observed.Bindings)
				}
			}
		})
	}
}

func TestGPTIdentityClassificationRejectsRepeatedKernelGeneration(t *testing.T) {
	first := gptBindingFixture("sda", 8, 0, 11,
		"fedcba98-7654-3210-fedc-ba9876543210", "00112233-4455-6677-8899-aabbccddeeff")
	second := gptBindingFixture("sdb", 8, 0, 11,
		"00112233-7654-3210-fedc-ba9876543210", "10112233-4455-6677-8899-aabbccddeeff")
	if _, err := classifyGPTPartitionIdentities([]diskPartitionBinding{first, second}); err == nil {
		t.Fatal("same transient block generation was accepted as two disks or a clone")
	}
}

func TestGPTIdentityCoverageKeepsUnsupportedMBROutsideSupportedSubset(t *testing.T) {
	bindings := []diskPartitionBinding{
		{
			DiskName: "sda", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 0, DiskSequence: 11},
			TableDisposition: partitionTableGPT, Scheme: "gpt",
			TableID: "fedcba98-7654-3210-fedc-ba9876543210",
		},
		{
			DiskName: "sdb", Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 12},
			TableDisposition: partitionTableUnsupported,
		},
	}

	observed, err := classifyGPTPartitionIdentities(bindings)
	if err != nil {
		t.Fatalf("GPT plus explicitly unsupported MBR should classify as partial coverage: %v", err)
	}
	if observed.CandidateCount != 2 || observed.GPTDiskCount != 1 ||
		observed.UnsupportedTableCount != 1 || observed.NoTableCount != 0 ||
		observed.Coverage != gptIdentityCoveragePartial ||
		observed.Bindings[0].TableIDStatus != gptIdentitySingletonObserved ||
		observed.Bindings[1].TableID != "" || observed.Bindings[1].Scheme != "" ||
		observed.Bindings[1].TableIDStatus != "" || len(observed.Bindings[1].Partitions) != 0 {
		t.Fatalf("unsupported MBR was treated as GPT identity evidence: %+v", observed)
	}
	if bindings[0].TableIDStatus != "" {
		t.Fatal("classification mutated the input GPT binding")
	}
}

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
		matched.Partitions[0].UUID != "00112233-4455-6677-8899-aabbccddeeff" ||
		matched.Partitions[0].TypeGUID != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ||
		matched.Partitions[0].TypeHint != gptTypeHintEFISystem {
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
	identitySet, err := observeCandidateGPTIdentities(discovery, current, results)
	if err != nil || identitySet.CandidateCount != len(discovery.candidates) ||
		identitySet.GPTDiskCount != 0 || identitySet.NoTableCount != 2 ||
		identitySet.Coverage != gptIdentityCoverageNone {
		t.Fatalf("complete no-GPT candidate set was misclassified: observation=%+v err=%v", identitySet, err)
	}
	if _, err := correlateCandidatePartitionTables(discovery, current, results[:1]); err == nil {
		t.Fatal("partial parser-result set was accepted")
	}
	if _, err := observeCandidateGPTIdentities(discovery, current, results[:1]); err == nil {
		t.Fatal("partial parser-result set was accepted by the identity classifier")
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

func TestObserveCandidateGPTIdentitiesClassifiesClonesAcrossCompleteCandidateSet(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	addDiscoveryGPTPartition(sysfs, "sdb", 8, 17)
	addDiscoveryGPTPartition(sysfs, "sdc", 8, 33)
	proc := discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", emptySwaps)
	discovery, err := discoverTrustedStorageWith(sysfs, proc, func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		sources := make([]volumeprobe.BlockDeviceSource, 0, len(devices))
		for _, device := range devices {
			writable, err := os.CreateTemp(t.TempDir(), "gpt-clone-observation-")
			if err != nil {
				return sources, err
			}
			name := writable.Name()
			if err := writable.Close(); err != nil {
				return sources, err
			}
			file, err := os.Open(name)
			if err != nil {
				return sources, err
			}
			sources = append(sources, volumeprobe.BlockDeviceSource{File: file, Generation: device.Generation})
		}
		return sources, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	current, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	const diskGUID = "fedcba98-7654-3210-fedc-ba9876543210"
	const partUUID = "00112233-4455-6677-8899-aabbccddeeff"
	result := func() volumeprobe.Result {
		return volumeprobe.Result{
			Status: "other-signature", SourceKind: "block-device",
			PartitionTable: &volumeprobe.PartitionTable{
				Scheme: "gpt", ID: diskGUID,
				Partitions: []volumeprobe.Partition{{
					Number: 1, Start512B: 2048, Size512B: 63455, UUID: partUUID,
					TypeID: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
				}},
			},
		}
	}
	observed, err := observeCandidateGPTIdentities(discovery, current, []volumeprobe.Result{result(), result()})
	if err != nil {
		t.Fatalf("complete cloned GPT candidate set should classify: %v", err)
	}
	if observed.CandidateCount != 2 || observed.GPTDiskCount != 2 ||
		observed.Coverage != gptIdentityCoverageAllCandidates || len(observed.Bindings) != 2 {
		t.Fatalf("classification did not retain the complete GPT candidate set: %+v", observed)
	}
	for index, binding := range observed.Bindings {
		if binding.TableIDStatus != gptIdentityAmbiguousObserved || len(binding.Partitions) != 1 ||
			binding.Partitions[0].UUIDStatus != gptIdentityAmbiguousObserved {
			t.Fatalf("complete-set clone collision was missed at index %d: %+v", index, binding)
		}
	}
	encoded, err := json.Marshal(observed)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("complete-set GPT identities must remain private: %s (err=%v)", encoded, err)
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

func gptBindingFixture(name string, major, minor uint32, diskSequence uint64, diskGUID, partUUID string) diskPartitionBinding {
	return diskPartitionBinding{
		DiskName: name,
		Generation: volumeprobe.BlockDeviceGeneration{
			Major: major, Minor: minor, DiskSequence: diskSequence,
		},
		TableDisposition: partitionTableGPT,
		Scheme:           "gpt",
		TableID:          diskGUID,
		Partitions: []kernelPartitionBinding{{
			KernelName: name + "1", Major: major, Minor: minor + 1, Number: 1,
			Start512B: 2048, Size512B: 4096, UUID: partUUID,
		}},
	}
}

func addDiscoveryGPTPartition(sysfs fstest.MapFS, disk string, major, minor uint32) {
	partition := disk + "1"
	parentPath := "devices/pci0000:00/block/" + disk
	partitionPath := parentPath + "/" + partition
	sysfs["class/block/"+partition] = &fstest.MapFile{
		Mode: fs.ModeSymlink, Data: []byte("../../" + partitionPath),
	}
	sysfs[partitionPath+"/dev"] = &fstest.MapFile{Data: []byte(fmt.Sprintf("%d:%d\n", major, minor))}
	sysfs[partitionPath+"/size"] = &fstest.MapFile{Data: []byte("63455\n")}
	sysfs[partitionPath+"/start"] = &fstest.MapFile{Data: []byte("2048\n")}
	sysfs[partitionPath+"/ro"] = &fstest.MapFile{Data: []byte("1\n")}
	sysfs[partitionPath+"/partition"] = &fstest.MapFile{Data: []byte("1\n")}
	sysfs[partitionPath+"/holders"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
}

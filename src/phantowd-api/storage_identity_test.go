// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestCorrelateMDStorageIdentityRequiresCompleteTopologyAndUniqueDiskEvidence(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	bindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("complete MD identity graph was not correlated: %+v, %v", bindings, err)
	}
	binding := bindings[0]
	if binding.arrayName != "md0" || binding.arrayUUID != "11111111-2222-3333-4444-555555555555" ||
		binding.arrayMajor != 9 || binding.arrayMinor != 0 || binding.arrayDiskSeq != 90 ||
		len(binding.memberDisks) != 2 || binding.memberDisks[0].memberName != "sda1" || binding.memberDisks[0].diskName != "sda" ||
		binding.memberDisks[1].memberName != "sdb1" || binding.memberDisks[1].diskName != "sdb" ||
		binding.memberDisks[0].serialEvidence == ([32]byte{}) || binding.memberDisks[1].wwnEvidence == ([32]byte{}) {
		t.Fatalf("partition-to-disk identity chain is incomplete: %+v", binding)
	}

	t.Run("ambiguous parent identity refuses", func(t *testing.T) {
		ambiguous := storage
		ambiguous.Observations = append([]blockObservation{}, storage.Observations...)
		ambiguous.Observations[1].SerialStatus = identityAmbiguous
		if _, err := correlateMDStorageIdentity(ambiguous, arrays); !errors.Is(err, errMDIdentityInventoryIncomplete) {
			t.Fatalf("ambiguous disk identity produced a binding: %v", err)
		}
	})

	t.Run("missing parent identities refuse", func(t *testing.T) {
		missing := storage
		missing.Observations = append([]blockObservation{}, storage.Observations...)
		missing.Observations[1].SerialStatus = identityUnavailable
		missing.Observations[1].WWNStatus = identityUnavailable
		missing.Observations[1].serialEvidence = [32]byte{}
		missing.Observations[1].wwnEvidence = [32]byte{}
		if _, err := correlateMDStorageIdentity(missing, arrays); !errors.Is(err, errMDIdentityInventoryIncomplete) {
			t.Fatalf("disk without durable identity evidence produced a binding: %v", err)
		}
	})

	t.Run("identity subset refuses", func(t *testing.T) {
		partial := arrays
		partial.identityInventoryComplete = false
		if _, err := correlateMDStorageIdentity(storage, partial); !errors.Is(err, errMDIdentityInventoryIncomplete) {
			t.Fatalf("partial array inventory produced a binding: %v", err)
		}
	})
}

func fixtureMDStorageIdentity() (storageSnapshot, mdArraySnapshot) {
	mdstat := "md0 : active raid1 sda1[0] sdb1[1]\n      1024 blocks super 1.2 [2/2] [UU]\n"
	sysfs := fixtureMDArraySysfs("md0")
	delete(sysfs, "class/block/md0/slaves/sda2")
	delete(sysfs, "class/block/md0/slaves/sdb2")
	sysfs["class/block/md0/slaves/sda1"] = &fstest.MapFile{Mode: fs.ModeIrregular}
	sysfs["class/block/md0/slaves/sdb1"] = &fstest.MapFile{Mode: fs.ModeIrregular}
	arrays := collectMDArrayInventory(fstest.MapFS{"mdstat": {Data: []byte(mdstat)}}, sysfs, time.Now())

	major8, minor0, minor1, minor16, minor17 := uint32(8), uint32(0), uint32(1), uint32(16), uint32(17)
	storage := storageSnapshot{
		SchemaVersion: 2, Scope: "kernel-sysfs-only", InventoryReadOnly: true,
		Observations: []blockObservation{
			{
				Name: "md0", Kind: "block", Major: 9, Minor: 0, SizeBytes: 1024 * 1024,
				SerialStatus: identityUnavailable, WWNStatus: identityUnavailable, diskSequence: 90,
				sysfsTarget: "devices/virtual/block/md0",
				lowerBlocks: []blockTopologyRef{
					{Name: "sda1", Kind: "partition", Major: 8, Minor: 1},
					{Name: "sdb1", Kind: "partition", Major: 8, Minor: 17},
				},
			},
			{
				Name: "sda", Kind: "block", Major: major8, Minor: minor0, SizeBytes: 1024 * 1024,
				SerialStatus: identityPresent, WWNStatus: identityPresent,
				serialEvidence: [32]byte{1}, wwnEvidence: [32]byte{2}, diskSequence: 41,
				sysfsTarget: "devices/pci0000:00/0000:00:01.0/block/sda",
			},
			{
				Name: "sda1", Kind: "partition", Major: major8, Minor: minor1, SizeBytes: 512 * 1024,
				PartitionNumber: 1, ParentName: "sda", ParentMajor: &major8, ParentMinor: &minor0,
				parentDiskSeq: 41, sysfsTarget: "devices/pci0000:00/0000:00:01.0/block/sda/sda1",
			},
			{
				Name: "sdb", Kind: "block", Major: major8, Minor: minor16, SizeBytes: 1024 * 1024,
				SerialStatus: identityPresent, WWNStatus: identityPresent,
				serialEvidence: [32]byte{3}, wwnEvidence: [32]byte{4}, diskSequence: 42,
				sysfsTarget: "devices/pci0000:00/0000:00:02.0/block/sdb",
			},
			{
				Name: "sdb1", Kind: "partition", Major: major8, Minor: minor17, SizeBytes: 512 * 1024,
				PartitionNumber: 1, ParentName: "sdb", ParentMajor: &major8, ParentMinor: &minor16,
				parentDiskSeq: 42, sysfsTarget: "devices/pci0000:00/0000:00:02.0/block/sdb/sdb1",
			},
		},
		DeviceCount: 5, Limitations: []string{}, collectionComplete: true,
	}
	return storage, arrays
}

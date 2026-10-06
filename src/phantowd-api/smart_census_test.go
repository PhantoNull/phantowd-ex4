// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestSMARTCensusIncludesInUseAndAmbiguousWholeLeaves(t *testing.T) {
	census, err := collectSMARTDiskCensus(context.Background(), fixtureDiscoverySysfs())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, disk := range census.disks {
		names = append(names, disk.name)
		if disk.generation.DiskSequence == 0 {
			t.Fatal("missing transient generation")
		}
		if disk.name == "sdb" || disk.name == "sdc" {
			if disk.serialStatus != identityAmbiguous || disk.wwnStatus != identityAmbiguous {
				t.Fatal("duplicate VPD evidence must remain explicitly ambiguous")
			}
		}
		if disk.name == "sdd" && !disk.removable {
			t.Fatal("removable observation lost")
		}
	}
	// sda contains the mounted-root partition in the import-policy fixture;
	// sde is an MD member; sdd is removable. None is a mount eligibility grant.
	if !reflect.DeepEqual(names, []string{"sda", "sdb", "sdc", "sdd", "sde"}) {
		t.Fatalf("unexpected leaf census: %v", names)
	}
	if census.snapshot.DeviceCount != 8 || len(census.snapshot.Observations) != 8 ||
		census.snapshot.BlockDevicesOpened || census.snapshot.ContentRead || census.snapshot.MutationsPerformed ||
		census.snapshot.StableIdentityAvailable || !sameSMARTDiskCensus(census, census) {
		t.Fatal("whole inventory or read-only contract lost")
	}
}

func TestSMARTCensusPreservesMissingIdentityAndReadOnlyState(t *testing.T) {
	sysfs := fixtureSysfs()
	physicalizeBlockNode(sysfs, "sda")
	delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg80")
	delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg83")
	sysfs["devices/pci0000:00/block/sda/ro"] = &fstest.MapFile{Data: []byte("1\n")}
	census, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil || len(census.disks) != 1 {
		t.Fatalf("missing VPD is not absence of transient disk observation: %v", err)
	}
	disk := census.disks[0]
	if disk.serialStatus != identityUnavailable || disk.wwnStatus != identityUnavailable || !disk.readOnly {
		t.Fatal("unknown VPD or read-only flag misrepresented")
	}
}

func TestSMARTCensusDoesNotMistakeNonVirtualStackForPhysicalLeaf(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	physicalizeBlockNode(sysfs, "md0")
	// Rebind the reciprocal holder to the new non-virtual location. A target
	// outside devices/virtual alone is not proof that the node is a leaf.
	sysfs["devices/pci0000:00/block/sde/holders/md0"].Data = []byte("../../md0")
	sysfs["devices/pci0000:00/block/md0/slaves/sde"].Data = []byte("../../sde")
	census, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil {
		t.Fatal(err)
	}
	for _, disk := range census.disks {
		if disk.name == "md0" {
			t.Fatal("stacked node included as a whole leaf")
		}
	}
	if len(census.disks) != 5 {
		t.Fatal("physical stack member was removed from the observation")
	}
}

func TestSMARTCensusPreservesInvalidVPDWithoutClaimingIdentity(t *testing.T) {
	sysfs := fixtureSysfs()
	physicalizeBlockNode(sysfs, "sda")
	sysfs["devices/pci0000:00/block/sda/device/vpd_pg80"].Data = []byte{0, 0x80, 0, 10}
	census, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil || len(census.disks) != 1 || census.disks[0].serialStatus != identityInvalid {
		t.Fatalf("invalid VPD lost or treated as identity: %v", err)
	}
}

func TestSMARTCensusCompleteEmptyIsDistinctFromInvalid(t *testing.T) {
	census, err := collectSMARTDiskCensus(context.Background(), fstest.MapFS{
		"class": {Mode: fs.ModeDir | 0o555}, "class/block": {Mode: fs.ModeDir | 0o555},
	})
	if err != nil || census.disks == nil || len(census.disks) != 0 || !sameSMARTDiskCensus(census, census) {
		t.Fatal("complete empty inventory lost")
	}
	if sameSMARTDiskCensus(smartDiskCensus{}, smartDiskCensus{}) {
		t.Fatal("zero samples accepted as a complete empty census")
	}
}

func TestSMARTCensusRefusesWholeInventoryFailureWithoutPartialView(t *testing.T) {
	for _, filename := range []string{
		"devices/pci0000:00/block/sda/dev",
		"devices/pci0000:00/block/sda/sda1/start",
		"devices/virtual/block/sdf/diskseq",
		"devices/virtual/block/md0/slaves/sde",
	} {
		t.Run(filename, func(t *testing.T) {
			sysfs := fixtureDiscoverySysfs()
			delete(sysfs, filename)
			census, err := collectSMARTDiskCensus(context.Background(), sysfs)
			if !errors.Is(err, errSMARTCensusIncomplete) || !reflect.DeepEqual(census, smartDiskCensus{}) {
				t.Fatalf("partial observation published: %v", err)
			}
		})
	}
}

func TestSMARTCensusRejectsDriftDuringCollection(t *testing.T) {
	for _, source := range []fs.FS{
		&changingDiskSequenceFS{MapFS: fixtureSysfs(), changeAt: 2},
		&lateChangingDiskSequenceFS{MapFS: fixtureSysfs()},
	} {
		census, err := collectSMARTDiskCensus(context.Background(), source)
		if err == nil || !reflect.DeepEqual(census, smartDiskCensus{}) {
			t.Fatal("generation drift published a census")
		}
	}
}

func TestSMARTCensusComparisonChecksEntireInventory(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(fstest.MapFS)
	}{
		{"unrelated virtual generation", func(f fstest.MapFS) { f["devices/virtual/block/sdf/diskseq"].Data = []byte("111\n") }},
		{"whole disk replacement", func(f fstest.MapFS) { f["devices/pci0000:00/block/sda/diskseq"].Data = []byte("112\n") }},
		{"same status new serial", func(f fstest.MapFS) {
			f["devices/pci0000:00/block/sda/device/vpd_pg80"].Data = makeVPDPage(0x80, []byte("replacement-serial"))
		}},
		{"partition extent", func(f fstest.MapFS) { f["devices/pci0000:00/block/sda/sda1/start"].Data = []byte("35\n") }},
		{"read only flag", func(f fstest.MapFS) { f["devices/pci0000:00/block/sda/ro"].Data = []byte("1\n") }},
		{"new disk", func(f fstest.MapFS) {
			addPhysicalBlockNode(f, "sdg", 8, 96, "new-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 8})
		}},
		{"stack detached", func(f fstest.MapFS) {
			delete(f, "devices/pci0000:00/block/sde/holders/md0")
			delete(f, "devices/virtual/block/md0/slaves/sde")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureDiscoverySysfs()
			before, err := collectSMARTDiskCensus(context.Background(), sysfs)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(sysfs)
			after, err := collectSMARTDiskCensus(context.Background(), sysfs)
			if err != nil {
				t.Fatal(err)
			}
			if sameSMARTDiskCensus(before, after) {
				t.Fatal("changed full inventory treated as the same census")
			}
		})
	}
}

func TestSMARTCensusComparisonRefusesForgedViews(t *testing.T) {
	for _, mutate := range []func(*smartDiskCensus){
		func(c *smartDiskCensus) { c.snapshot.collectionComplete = false },
		func(c *smartDiskCensus) { c.snapshot.DeviceCount-- },
		func(c *smartDiskCensus) { c.disks = c.disks[:1] },
		func(c *smartDiskCensus) { c.disks[0].generation.DiskSequence++ },
		func(c *smartDiskCensus) { c.disks = nil },
	} {
		census, err := collectSMARTDiskCensus(context.Background(), fixtureDiscoverySysfs())
		if err != nil {
			t.Fatal(err)
		}
		mutate(&census)
		if sameSMARTDiskCensus(census, census) {
			t.Fatal("invalid baseline accepted even against itself")
		}
	}
}

func TestSMARTCensusCancellationAndPrivacy(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if census, err := collectSMARTDiskCensus(canceled, nil); err == nil || !reflect.DeepEqual(census, smartDiskCensus{}) {
		t.Fatal("invalid inputs accepted")
	}
	if census, err := collectSMARTDiskCensus(canceled, fixtureSysfs()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(census, smartDiskCensus{}) {
		t.Fatal("canceled request published evidence")
	}
	if _, err := collectSMARTDiskCensus(nil, fixtureSysfs()); !errors.Is(err, errSMARTCensusIncomplete) {
		t.Fatal("nil context accepted")
	}
	for _, value := range []any{smartDiskCensus{}, smartDiskObservation{}} {
		if _, err := json.Marshal(value); !errors.Is(err, errSMARTCensusPrivate) {
			t.Fatal("private census serialized")
		}
	}
	for _, value := range []any{new(smartDiskCensus), new(smartDiskObservation)} {
		if err := json.Unmarshal([]byte("{}"), value); !errors.Is(err, errSMARTCensusPrivate) {
			t.Fatal("JSON accepted as trusted census")
		}
	}
}

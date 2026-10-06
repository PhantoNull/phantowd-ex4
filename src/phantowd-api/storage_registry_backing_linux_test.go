//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Independent fixture inputs are correlated through the production validator;
// do not synthesize roots from identities under test.
func registryMDBackingFixture(t *testing.T, kind string) trustedMountedExtCensus {
	t.Helper()
	storage, md := fixtureMDStorageIdentity()
	arrays, err := correlateMDStorageIdentity(storage, md)
	if err != nil {
		t.Fatal(err)
	}
	major, minor := uint32(9), uint32(0)
	if kind == "md-partition" {
		parentMajor, parentMinor := major, minor
		storage.Observations = append(storage.Observations, blockObservation{
			Name: "md0p1", Kind: "partition", Major: 259, Minor: 1, SizeBytes: 524288,
			PartitionNumber: 1, ParentName: "md0", ParentMajor: &parentMajor, ParentMinor: &parentMinor,
			parentDiskSeq: 90, sysfsTarget: "devices/virtual/block/md0/md0p1"})
		major, minor = 259, 1
	} else if kind == "md-backed-stack" || kind == "other-block-stack" {
		lower := storage.Observations[0]
		if kind == "other-block-stack" {
			lower = storage.Observations[1]
		}
		storage.Observations = append(storage.Observations, blockObservation{
			Name: "dm-0", Kind: "block", Major: 253, Minor: 0, SizeBytes: 524288,
			SerialStatus: identityUnavailable, WWNStatus: identityUnavailable,
			diskSequence: 91, sysfsTarget: "devices/virtual/block/dm-0",
			lowerBlocks: []blockTopologyRef{{Name: lower.Name, Kind: lower.Kind, Major: lower.Major, Minor: lower.Minor, DiskSequence: lower.diskSequence}}})
		major, minor = 253, 0
	}
	sort.Slice(storage.Observations, func(i, j int) bool { return storage.Observations[i].Name < storage.Observations[j].Name })
	storage.DeviceCount = len(storage.Observations)
	mounts, err := collectMountInventory(fstest.MapFS{"self/mountinfo": {Data: []byte("36 0 0:1 / / rw - tmpfs tmpfs rw\n")}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mounts.Mounts = append(mounts.Mounts, mountObservation{MountPoint: "/data", Filesystem: "ext4", DeviceMajor: major,
		DeviceMinor: minor, ReadOnly: true, mountInfoID: 37, filesystemRoot: "/"})
	mounts.MountCount = len(mounts.Mounts)
	roots := mountguard.MountedInventory{Mounts: []mountguard.MountedIdentity{{Anchor: "/data",
		FilesystemUUID: mountedReviewUUID, DeviceMajor: major, DeviceMinor: minor, MountID: 70001}}, ConflictingUUIDs: []string{}}
	identities, err := correlateObservedMountedStorageIdentity(storage, arrays, roots)
	if err != nil {
		t.Fatal(err)
	}
	_, coverage, err := planMountedExtCensus(storage, mounts)
	if err != nil {
		t.Fatal(err)
	}
	census := trustedMountedExtCensus{storage: storage, arrays: arrays, mounts: mounts, roots: roots, identities: identities, coverage: coverage}
	if validateMountedExtCensus(census) != nil {
		t.Fatal("invalid complete MD backing fixture")
	}
	return census
}

func TestRegisteredBackingDistinguishesCompleteScopedTopology(t *testing.T) {
	for _, kind := range []string{"physical-partition", "physical-disk", "md-device", "md-partition", "md-backed-stack", "other-block-stack"} {
		t.Run(kind, func(t *testing.T) {
			var census trustedMountedExtCensus
			if kind == "physical-partition" || kind == "physical-disk" {
				census = collectMountedReviewFixture(t, func(_ fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
					if kind == "physical-disk" {
						proc["self/mountinfo"].Data = []byte("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n38 36 8:0 / /data ro - ext4 /dev/sda ro\n")
						roots.Mounts[0].DeviceMinor = 0
					}
				})
			} else {
				census = registryMDBackingFixture(t, kind)
			}
			snapshot := registeredReviewFixture(t, shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID})
			before := census.identities[0]
			got, err := reviewRegisteredBacking(snapshot, census)
			disks, arrays := 1, 0
			if kind == "md-device" || kind == "md-partition" || kind == "md-backed-stack" {
				disks, arrays = 2, 1
			}
			if err != nil || got.registryRevision != 11 || got.coverage != census.coverage || got.objectCount != 1 ||
				got.unclaimedObjectCount != 0 || len(got.volumes) != 1 || got.volumes[0].kind != kind ||
				got.volumes[0].physicalDiskCount != disks || got.volumes[0].mdArrayCount != arrays ||
				got.volumes[0].observed.status != "observed-in-scope" {
				t.Fatalf("incorrect topology: %+v, %v", got, err)
			}
			if !reflect.DeepEqual(before, census.identities[0]) {
				t.Fatal("backing review mutated input")
			}
			if _, err := json.Marshal(got); err == nil {
				t.Fatal("private backing review serialized")
			}
			if json.Unmarshal([]byte(`{}`), &got) == nil {
				t.Fatal("request constructed backing review")
			}
		})
	}
}

func TestRegisteredBackingAliasesClonesMissingAndUnresolved(t *testing.T) {
	for _, kind := range []string{"alias", "clone", "missing", "unresolved", "empty"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, func(sysfs fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
				if kind == "unresolved" {
					delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg80")
					delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg83")
				}
				if kind != "alias" && kind != "clone" {
					return
				}
				alias := roots.Mounts[0]
				alias.Anchor, alias.MountID = "/other", 70002
				if kind == "clone" {
					addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "fixture-other-physical-disk", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
					physicalizeBlockNode(sysfs, "sdb")
					alias.DeviceMinor = 16
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:16 / /other ro - ext4 /dev/sdb ro\n")...)
					roots.ConflictingUUIDs = []string{mountedReviewUUID}
				} else {
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:1 / /other ro - ext4 /dev/sda1 ro\n")...)
				}
				roots.Mounts = append(roots.Mounts, alias)
			})
			volumes := []shareconfig.Volume{{ID: "books", FilesystemUUID: mountedReviewUUID}}
			if kind == "missing" {
				volumes[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			if kind == "empty" {
				volumes = []shareconfig.Volume{}
			}
			got, err := reviewRegisteredBacking(registeredReviewFixture(t, volumes...), census)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "empty" {
				if got.volumes == nil || len(got.volumes) != 0 || got.unclaimedObjectCount != 1 {
					t.Fatal("empty registry hid unclaimed backing")
				}
				return
			}
			if len(got.volumes) != 1 {
				t.Fatal("lost volume")
			}
			backing := got.volumes[0]
			if kind == "clone" || kind == "missing" {
				if backing.kind != "" || backing.physicalDiskCount != 0 || backing.mdArrayCount != 0 {
					t.Fatal("missing/cloned UUID chose a backing")
				}
				if kind == "clone" && backing.observed.status != "ambiguous-in-scope" {
					t.Fatal("clone became unique")
				}
				if kind == "missing" && backing.observed.status != "not-observed-in-scope" {
					t.Fatal("missing became observed")
				}
			} else {
				if backing.kind != "physical-partition" || backing.physicalDiskCount != 1 || backing.mdArrayCount != 0 {
					t.Fatal("lost scoped topology")
				}
				if backing.observed.scopedDiskEvidenceUnresolved != (kind == "unresolved") {
					t.Fatal("topology hid unresolved physical evidence")
				}
				if kind == "alias" && backing.observed.aliasCount != 2 {
					t.Fatal("alias inflated backing count")
				}
			}
		})
	}
}

func TestRegisteredBackingWholeCensusAndSnapshotRequiredBeforeEmptyClaims(t *testing.T) {
	if got, err := reviewRegisteredBacking(volumeregistry.Snapshot{}, collectMountedReviewFixture(t, nil)); err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredBackingReview{}) {
		t.Fatal("zero snapshot accepted")
	}
	snapshot := registeredReviewFixture(t)
	for _, kind := range []string{"coverage", "unclaimed-identity", "roots", "storage", "arrays"} {
		t.Run(kind, func(t *testing.T) {
			census := registryMDBackingFixture(t, "md-device")
			switch kind {
			case "coverage":
				census.coverage.mountCount++
			case "unclaimed-identity":
				census.identities[0].arrays[0].arrayUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "roots":
				census.roots.Mounts = nil
			case "storage":
				census.storage.collectionComplete = false
			case "arrays":
				census.arrays = nil
			}
			if got, err := reviewRegisteredBacking(snapshot, census); err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredBackingReview{}) {
				t.Fatal("invalid unclaimed census yielded partial backing")
			}
		})
	}
}

func TestRegisteredBackingOrderBoundsAndOwnedResult(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	volumes := []shareconfig.Volume{{ID: "z-books", FilesystemUUID: mountedReviewUUID},
		{ID: "a-missing", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}}
	got, err := reviewRegisteredBacking(registeredReviewFixture(t, volumes...), census)
	if err != nil || len(got.volumes) != 2 || got.volumes[0].observed.volumeID != "a-missing" || got.volumes[1].kind != "physical-partition" {
		t.Fatal("backing result lost deterministic ordering", err)
	}
	volumes[0], volumes[1] = volumes[1], volumes[0]
	reordered, err := reviewRegisteredBacking(registeredReviewFixture(t, volumes...), census)
	if err != nil || !reflect.DeepEqual(got, reordered) {
		t.Fatal("claim order changed backing observation", err)
	}
	got.volumes[1].kind = "changed-by-caller"
	fresh, err := reviewRegisteredBacking(registeredReviewFixture(t, volumes...), census)
	if err != nil || !reflect.DeepEqual(fresh, reordered) {
		t.Fatal("result shares mutable storage", err)
	}
	volumes = []shareconfig.Volume{{ID: "volume-00", FilesystemUUID: mountedReviewUUID}}
	for i := 1; i < 16; i++ {
		volumes = append(volumes, shareconfig.Volume{ID: shareconfig.VolumeID(fmt.Sprintf("volume-%02d", i)),
			FilesystemUUID: shareconfig.FilesystemUUID(fmt.Sprintf("77777777-8888-9999-aaaa-%012x", i))})
	}
	bounded, err := reviewRegisteredBacking(registeredReviewFixture(t, volumes...), census)
	if err != nil || len(bounded.volumes) != 16 || bounded.volumes[0].kind != "physical-partition" {
		t.Fatal("maximum bounded registry lost backing observations", err)
	}
	for _, missing := range bounded.volumes[1:] {
		if missing.observed.status != "not-observed-in-scope" || missing.kind != "" || missing.physicalDiskCount != 0 || missing.mdArrayCount != 0 {
			t.Fatal("bounded missing claim selected a backing")
		}
	}
}

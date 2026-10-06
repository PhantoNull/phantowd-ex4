//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const mountedReviewUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"

func mountedReviewPolicy(volumes ...shareconfig.Volume) shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 7,
		Volumes: append([]shareconfig.Volume{}, volumes...), Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

func collectMountedReviewFixture(t *testing.T, mutate func(fstest.MapFS, fstest.MapFS, *mountguard.MountedInventory)) trustedMountedExtCensus {
	t.Helper()
	sysfs, proc, roots := mountedCensusFixture()
	if mutate != nil {
		mutate(sysfs, proc, &roots)
	}
	census, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc,
		func([]string) (mountguard.MountedInventory, error) { return roots, nil })
	if err != nil {
		t.Fatal("fixture census unavailable", err)
	}
	return census
}

func TestDesiredMountedReviewKeepsExpectedIDsSeparateFromObservedObjects(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	policy := mountedReviewPolicy(
		shareconfig.Volume{ID: "z-missing", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"},
		shareconfig.Volume{ID: "logical-books", FilesystemUUID: mountedReviewUUID})
	before := census.identities[0]
	review, err := reviewDesiredMountedVolumes(policy, census)
	want := []desiredMountedVolumeObservation{
		{volumeID: "logical-books", status: "observed-in-scope", objectCount: 1, aliasCount: 1},
		{volumeID: "z-missing", status: "not-observed-in-scope"},
	}
	if err != nil || review.policyRevision != 7 || review.coverage != census.coverage || review.objectCount != 1 ||
		review.unclaimedObjectCount != 0 || !reflect.DeepEqual(review.volumes, want) {
		t.Fatalf("policy claims were promoted or scoped observation lost: %+v, %v", review, err)
	}
	if !reflect.DeepEqual(before, census.identities[0]) || policy.Volumes[0].ID != "z-missing" {
		t.Fatal("review mutated its input")
	}
	policy.Volumes[0], policy.Volumes[1] = policy.Volumes[1], policy.Volumes[0]
	reordered, err := reviewDesiredMountedVolumes(policy, census)
	if err != nil || !reflect.DeepEqual(review, reordered) {
		t.Fatal("desired ordering changed review", err)
	}
	if _, err := json.Marshal(review); err == nil {
		t.Fatal("private review serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &review); err == nil {
		t.Fatal("request data could construct review")
	}
}

func TestDesiredMountedReviewAliasesAreOneObjectNotAChosenPath(t *testing.T) {
	census := collectMountedReviewFixture(t, func(_ fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
		proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:1 / /data-alias ro - ext4 /dev/sda1 ro\n")...)
		alias := roots.Mounts[0]
		alias.Anchor, alias.MountID = "/data-alias", 70002
		roots.Mounts = append(roots.Mounts, alias)
	})
	review, err := reviewDesiredMountedVolumes(mountedReviewPolicy(shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}), census)
	if err != nil || review.objectCount != 1 || len(review.volumes) != 1 ||
		review.volumes[0].status != "observed-in-scope" || review.volumes[0].objectCount != 1 || review.volumes[0].aliasCount != 2 {
		t.Fatal("same kernel object aliases became cloned volumes or one hidden alias", review, err)
	}
}

func TestDesiredMountedReviewClonedUUIDsRemainAmbiguous(t *testing.T) {
	census := collectMountedReviewFixture(t, func(sysfs fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
		addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "fixture-other-physical-disk", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
		physicalizeBlockNode(sysfs, "sdb")
		proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:16 / /data-clone ro - ext4 /dev/sdb ro\n")...)
		clone := roots.Mounts[0]
		clone.Anchor, clone.MountID, clone.DeviceMinor = "/data-clone", 70002, 16
		roots.Mounts = append(roots.Mounts, clone)
		roots.ConflictingUUIDs = []string{mountedReviewUUID}
	})
	review, err := reviewDesiredMountedVolumes(mountedReviewPolicy(shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}), census)
	if err != nil || review.objectCount != 2 || len(review.volumes) != 1 ||
		review.volumes[0].status != "ambiguous-in-scope" || review.volumes[0].objectCount != 2 || review.volumes[0].aliasCount != 2 {
		t.Fatal("cloned filesystem UUID arbitrarily chose one object", review, err)
	}
	empty, err := reviewDesiredMountedVolumes(mountedReviewPolicy(), census)
	if err != nil || empty.objectCount != 2 || empty.unclaimedObjectCount != 2 || empty.volumes == nil || len(empty.volumes) != 0 {
		t.Fatal("empty desired policy hid unclaimed cloned objects", empty, err)
	}
}

func TestDesiredMountedReviewKeepsUnresolvedDiskEvidenceExplicit(t *testing.T) {
	for _, kind := range []string{"missing", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, func(sysfs fstest.MapFS, _ fstest.MapFS, _ *mountguard.MountedInventory) {
				delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg80")
				delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg83")
			})
			if kind == "ambiguous" {
				for i := range census.storage.Observations {
					if census.storage.Observations[i].Name == "sda" {
						census.storage.Observations[i].SerialStatus = identityAmbiguous
					}
				}
				census.identities[0].physicalDisks[0].serialStatus = identityAmbiguous
			}
			review, err := reviewDesiredMountedVolumes(mountedReviewPolicy(shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}), census)
			if err != nil || review.volumes[0].status != "observed-in-scope" || !review.volumes[0].scopedDiskEvidenceUnresolved {
				t.Fatal("scoped UUID observation hid missing/ambiguous physical identity", review, err)
			}
		})
	}
}

func TestDesiredMountedReviewRejectsMalformedWholeCensusBeforeSubset(t *testing.T) {
	for _, scenario := range []string{"zero", "coverage", "missing identity", "missing arrays", "wrong anchor", "wrong UUID", "valid UUID changed", "unique mount ID changed",
		"wrong source", "wrong generation", "wrong VPD", "wrong conflict", "missing disks", "missing array slice", "incomplete storage", "incomplete mounts",
		"missing roots", "missing root conflicts", "wrong root device", "wrong root conflict"} {
		t.Run(scenario, func(t *testing.T) {
			census := collectMountedReviewFixture(t, nil)
			switch scenario {
			case "zero":
				census = trustedMountedExtCensus{}
			case "coverage":
				census.coverage.observedRootCount++
			case "missing identity":
				census.identities = []mountedStorageIdentity{}
			case "missing arrays":
				census.arrays = nil
			case "wrong anchor":
				census.identities[0].anchor = "/unselected"
			case "wrong UUID":
				census.identities[0].filesystemUUID = "unknown"
			case "valid UUID changed":
				census.identities[0].filesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "unique mount ID changed":
				census.identities[0].mountID++
			case "wrong source":
				census.identities[0].sourceName = "sdb"
			case "wrong generation":
				census.identities[0].physicalDisks[0].diskSequence++
			case "wrong VPD":
				census.identities[0].physicalDisks[0].serialEvidence[0] ^= 1
			case "wrong conflict":
				census.identities[0].filesystemUUIDConflict = true
			case "missing disks":
				census.identities[0].physicalDisks = nil
			case "missing array slice":
				census.identities[0].arrays = nil
			case "incomplete storage":
				census.storage.collectionComplete = false
			case "incomplete mounts":
				census.mounts.collectionComplete = false
			case "missing roots":
				census.roots.Mounts = nil
			case "missing root conflicts":
				census.roots.ConflictingUUIDs = nil
			case "wrong root device":
				census.roots.Mounts[0].DeviceMinor++
			case "wrong root conflict":
				census.roots.ConflictingUUIDs = []string{mountedReviewUUID}
			}
			// No desired volumes is not permission to skip validating an
			// unrelated malformed/partial observed object.
			got, err := reviewDesiredMountedVolumes(mountedReviewPolicy(), census)
			if !errors.Is(err, errMountedVolumeReviewIncomplete) || !reflect.DeepEqual(got, desiredMountedVolumeReview{}) {
				t.Fatal("partial or unclaimed bad evidence yielded a review", got, err)
			}
		})
	}
}

func TestDesiredMountedReviewRefusesInvalidPolicyWithoutPartialResult(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	for _, scenario := range []string{"zero revision", "duplicate ID", "duplicate UUID", "invalid ID", "invalid UUID", "nil volumes"} {
		t.Run(scenario, func(t *testing.T) {
			policy := mountedReviewPolicy(shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID})
			switch scenario {
			case "zero revision":
				policy.Revision = 0
			case "duplicate ID":
				policy.Volumes = append(policy.Volumes, shareconfig.Volume{ID: "books", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"})
			case "duplicate UUID":
				policy.Volumes = append(policy.Volumes, shareconfig.Volume{ID: "other", FilesystemUUID: mountedReviewUUID})
			case "invalid ID":
				policy.Volumes[0].ID = "../data"
			case "invalid UUID":
				policy.Volumes[0].FilesystemUUID = "unknown"
			case "nil volumes":
				policy.Volumes = nil
			}
			got, err := reviewDesiredMountedVolumes(policy, census)
			if !errors.Is(err, errMountedVolumeReviewIncomplete) || !reflect.DeepEqual(got, desiredMountedVolumeReview{}) {
				t.Fatal("invalid desired policy yielded partial review", got, err)
			}
		})
	}
}

func TestDesiredMountedReviewEmptyCompleteScope(t *testing.T) {
	census := collectMountedReviewFixture(t, func(_ fstest.MapFS, proc fstest.MapFS, _ *mountguard.MountedInventory) {
		proc["self/mountinfo"].Data = []byte("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
	})
	policy := mountedReviewPolicy(shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID})
	review, err := reviewDesiredMountedVolumes(policy, census)
	if err != nil || review.objectCount != 0 || review.unclaimedObjectCount != 0 || len(review.volumes) != 1 ||
		review.volumes[0].status != "not-observed-in-scope" || review.volumes[0].aliasCount != 0 || review.coverage.processRootExcluded != 1 {
		t.Fatal("empty completed scope became physical absence or unavailable evidence", review, err)
	}
	census.arrays = nil
	if got, err := reviewDesiredMountedVolumes(policy, census); err == nil || !reflect.DeepEqual(got, desiredMountedVolumeReview{}) {
		t.Fatal("empty scoped result bypassed complete topology validation", got, err)
	}
}

func TestDesiredMountedReviewMaximumBoundsAndMountOrder(t *testing.T) {
	makeCensus := func(reverse bool) trustedMountedExtCensus {
		return collectMountedReviewFixture(t, func(_ fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
			lines := []string{"36 0 8:1 / / rw - ext4 /dev/sda1 rw"}
			roots.Mounts = []mountguard.MountedIdentity{}
			for i := 0; i < maxMountedFilesystemAnchors; i++ {
				anchor := fmt.Sprintf("/data%03d", i)
				lines = append(lines, fmt.Sprintf("%d 36 8:1 / %s ro - ext4 /dev/sda1 ro", i+37, anchor))
				roots.Mounts = append(roots.Mounts, mountguard.MountedIdentity{Anchor: anchor, FilesystemUUID: mountedReviewUUID,
					MountID: uint64(70001 + i), DeviceMajor: 8, DeviceMinor: 1})
			}
			if reverse {
				for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
					lines[i], lines[j] = lines[j], lines[i]
				}
			}
			proc["self/mountinfo"].Data = []byte(strings.Join(lines, "\n") + "\n")
		})
	}
	volumes := []shareconfig.Volume{{ID: "books", FilesystemUUID: mountedReviewUUID}}
	for i := 1; i < shareconfig.MaxVolumes; i++ {
		volumes = append(volumes, shareconfig.Volume{ID: shareconfig.VolumeID(fmt.Sprintf("missing-%02d", i)),
			FilesystemUUID: shareconfig.FilesystemUUID(fmt.Sprintf("77777777-8888-9999-aaaa-%012x", i))})
	}
	policy := mountedReviewPolicy(volumes...)
	review, err := reviewDesiredMountedVolumes(policy, makeCensus(false))
	if err != nil || review.objectCount != 1 || len(review.volumes) != 16 || review.volumes[0].volumeID != "books" ||
		review.volumes[0].objectCount != 1 || review.volumes[0].aliasCount != 64 {
		t.Fatal("maximum desired/alias bounds lost coverage", review, err)
	}
	reversed, err := reviewDesiredMountedVolumes(policy, makeCensus(true))
	if err != nil || !reflect.DeepEqual(review, reversed) {
		t.Fatal("mountinfo record order changed scoped result", err)
	}
	policy.Volumes = append(policy.Volumes, shareconfig.Volume{ID: "seventeenth", FilesystemUUID: "99999999-8888-7777-aaaa-bbbbbbbbbbbb"})
	if got, err := reviewDesiredMountedVolumes(policy, makeCensus(false)); err == nil || !reflect.DeepEqual(got, desiredMountedVolumeReview{}) {
		t.Fatal("excess desired collection returned partial result", got, err)
	}
}

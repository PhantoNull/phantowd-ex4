//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func registeredReviewFixture(t *testing.T, volumes ...shareconfig.Volume) volumeregistry.Snapshot {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: 11, Volumes: append([]shareconfig.Volume{}, volumes...)}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "volumes.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := volumeregistry.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	snapshot, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestRegisteredMountedReviewExplicitIDsMissingAliasesAndClones(t *testing.T) {
	for _, kind := range []string{"single", "alias", "clone", "missing", "empty"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, func(sysfs, proc fstest.MapFS, roots *mountguard.MountedInventory) {
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
			volumes := []shareconfig.Volume{{ID: "explicit-books", FilesystemUUID: mountedReviewUUID}}
			if kind == "missing" {
				volumes[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			if kind == "empty" {
				volumes = []shareconfig.Volume{}
			}
			snapshot := registeredReviewFixture(t, volumes...)
			got, err := reviewRegisteredMountedVolumes(snapshot, census)
			if err != nil || got.registryRevision != 11 || got.coverage != census.coverage || got.volumes == nil {
				t.Fatal("protected registry review lost provenance/scope", err)
			}
			if kind == "empty" {
				if len(got.volumes) != 0 || got.objectCount != 1 || got.unclaimedObjectCount != 1 {
					t.Fatal("empty registry hid unclaimed observed object")
				}
			} else {
				want := desiredMountedVolumeObservation{volumeID: "explicit-books", status: "observed-in-scope", objectCount: 1, aliasCount: 1}
				if kind == "alias" {
					want.aliasCount = 2
				}
				if kind == "clone" {
					want.status = "ambiguous-in-scope"
					want.objectCount = 2
					want.aliasCount = 2
				}
				if kind == "missing" {
					want.status = "not-observed-in-scope"
					want.objectCount = 0
					want.aliasCount = 0
				}
				if len(got.volumes) != 1 || got.volumes[0] != want {
					t.Fatal("registry selected path/adopted missing or cloned identity", got.volumes)
				}
			}
			if _, err := json.Marshal(got); err == nil {
				t.Fatal("private registry review serialized")
			}
			if err := json.Unmarshal([]byte(`{}`), &got); err == nil {
				t.Fatal("request constructed registry review")
			}
		})
	}
}

func TestRegisteredMountedReviewRejectsWholeUnclaimedCensusAndUntrustedSnapshot(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	if got, err := reviewRegisteredMountedVolumes(volumeregistry.Snapshot{}, census); err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredMountedVolumeReview{}) {
		t.Fatal("unprotected claims trusted")
	}
	snapshot := registeredReviewFixture(t)
	for _, kind := range []string{"coverage", "roots", "derived-uuid", "storage", "arrays"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, nil)
			switch kind {
			case "coverage":
				census.coverage.observedRootCount++
			case "roots":
				census.roots.Mounts = nil
			case "derived-uuid":
				census.identities[0].filesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "storage":
				census.storage.collectionComplete = false
			case "arrays":
				census.arrays = nil
			}
			if got, err := reviewRegisteredMountedVolumes(snapshot, census); err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredMountedVolumeReview{}) {
				t.Fatal("unclaimed incomplete census yielded partial result")
			}
		})
	}
}

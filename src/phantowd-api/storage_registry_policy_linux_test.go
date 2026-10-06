//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func registryPolicyFixture(volumes ...shareconfig.Volume) fileservice.Config {
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 7,
		Shares: mountedReviewPolicy(volumes...), NFS: nfsconfig.Policy{Format: nfsconfig.Format,
			SchemaVersion: 1, Revision: 7, VolumeRevision: 7, Exports: []nfsconfig.Export{}}}
}

func TestRegistryPolicyReviewSeparatesRevisionsAndProtocolReferences(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	volumes := []shareconfig.Volume{{ID: "explicit-books", FilesystemUUID: mountedReviewUUID},
		{ID: "not-mounted", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}}
	snapshot := registeredReviewFixture(t, volumes...)
	policy := registryPolicyFixture(volumes...)
	policy.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	policy.Shares.Shares = []shareconfig.Share{{ID: "books-share", Name: "Books", VolumeID: "explicit-books", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	policy.NFS.Exports = []nfsconfig.Export{{ID: "11111111-2222-3333-4444-555555555555", VolumeID: "explicit-books", RelativePath: "audio",
		Clients: []nfsconfig.Client{{Network: "192.0.2.0/24", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
	before, _ := json.Marshal(policy)
	got, err := reviewRegisteredPolicyVolumes(policy, snapshot, census)
	want := []policyRegisteredVolumeObservation{{observed: desiredMountedVolumeObservation{volumeID: "explicit-books", status: "observed-in-scope", objectCount: 1, aliasCount: 1}, smbShareCount: 1, nfsExportCount: 1},
		{observed: desiredMountedVolumeObservation{volumeID: "not-mounted", status: "not-observed-in-scope"}}}
	if err != nil || got.policyRevision != 7 || got.registryRevision != 11 || got.registeredCount != 2 ||
		got.unreferencedRegisteredCount != 0 || got.coverage != census.coverage || !reflect.DeepEqual(got.volumes, want) {
		t.Fatal("registry/policy authority or protocol references confused", got, err)
	}
	after, _ := json.Marshal(policy)
	if string(before) != string(after) {
		t.Fatal("review altered desired policy")
	}
	policy.Shares.Volumes[0], policy.Shares.Volumes[1] = policy.Shares.Volumes[1], policy.Shares.Volumes[0]
	reordered, err := reviewRegisteredPolicyVolumes(policy, snapshot, census)
	if err != nil || !reflect.DeepEqual(got, reordered) {
		t.Fatal("input order changed registry-policy review")
	}
	if _, err := json.Marshal(got); err == nil {
		t.Fatal("private policy registry review serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &got); err == nil {
		t.Fatal("request constructed policy registry review")
	}
}

func TestRegistryPolicyReviewDoesNotRebindByUUIDOrOverwriteConflict(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	snapshot := registeredReviewFixture(t, shareconfig.Volume{ID: "explicit-books", FilesystemUUID: mountedReviewUUID})
	for _, kind := range []string{"unknown-id-same-uuid", "same-id-wrong-uuid", "no-registry"} {
		t.Run(kind, func(t *testing.T) {
			volume := shareconfig.Volume{ID: "explicit-books", FilesystemUUID: mountedReviewUUID}
			active := snapshot
			status := "not-registered"
			if kind == "unknown-id-same-uuid" {
				volume.ID = "different-logical-id"
			}
			if kind == "same-id-wrong-uuid" {
				volume.FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
				status = "registry-policy-conflict"
			}
			if kind == "no-registry" {
				active = registeredReviewFixture(t)
			}
			got, err := reviewRegisteredPolicyVolumes(registryPolicyFixture(volume), active, census)
			if err != nil || len(got.volumes) != 1 || got.volumes[0].observed != (desiredMountedVolumeObservation{volumeID: volume.ID, status: status}) {
				t.Fatal("UUID selected registration or conflict leaked observed backing", got, err)
			}
		})
	}
}

func TestRegistryPolicyReviewPreservesAliasCloneAndUnresolvedEvidence(t *testing.T) {
	for _, kind := range []string{"alias", "clone", "unresolved"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, func(sysfs, proc fstest.MapFS, roots *mountguard.MountedInventory) {
				if kind == "unresolved" {
					delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg80")
					delete(sysfs, "devices/pci0000:00/block/sda/device/vpd_pg83")
					return
				}
				alias := roots.Mounts[0]
				alias.Anchor, alias.MountID = "/other", 70002
				if kind == "clone" {
					addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "fixture-other-physical-disk", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
					physicalizeBlockNode(sysfs, "sdb")
					alias.DeviceMinor = 16
					roots.ConflictingUUIDs = []string{mountedReviewUUID}
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:16 / /other ro - ext4 /dev/sdb ro\n")...)
				} else {
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:1 / /other ro - ext4 /dev/sda1 ro\n")...)
				}
				roots.Mounts = append(roots.Mounts, alias)
			})
			volume := shareconfig.Volume{ID: "explicit-books", FilesystemUUID: mountedReviewUUID}
			got, err := reviewRegisteredPolicyVolumes(registryPolicyFixture(volume), registeredReviewFixture(t, volume), census)
			if err != nil || len(got.volumes) != 1 {
				t.Fatal(err)
			}
			observed := got.volumes[0].observed
			if kind == "alias" && (observed.objectCount != 1 || observed.aliasCount != 2 || observed.status != "observed-in-scope") {
				t.Fatal("alias became separate backing")
			}
			if kind == "clone" && (observed.objectCount != 2 || observed.aliasCount != 2 || observed.status != "ambiguous-in-scope") {
				t.Fatal("clone arbitrarily selected")
			}
			if kind == "unresolved" && !observed.scopedDiskEvidenceUnresolved {
				t.Fatal("unresolved identity hidden")
			}
		})
	}
}

func TestRegistryPolicyReviewRefusesWholeIncompleteAndSplitPolicy(t *testing.T) {
	snapshot := registeredReviewFixture(t)
	for _, kind := range []string{"zero-policy", "shares-revision", "nfs-revision", "nfs-binding", "nil-users", "missing-snapshot", "incomplete-storage", "incomplete-roots", "wrong-derived-uuid"} {
		t.Run(kind, func(t *testing.T) {
			policy := registryPolicyFixture()
			census := collectMountedReviewFixture(t, nil)
			active := snapshot
			switch kind {
			case "zero-policy":
				policy = fileservice.Config{}
			case "shares-revision":
				policy.Shares.Revision++
			case "nfs-revision":
				policy.NFS.Revision++
			case "nfs-binding":
				policy.NFS.VolumeRevision++
			case "nil-users":
				policy.Shares.Users = nil
			case "missing-snapshot":
				active = volumeregistry.Snapshot{}
			case "incomplete-storage":
				census.storage.collectionComplete = false
			case "incomplete-roots":
				census.roots.Mounts = nil
			case "wrong-derived-uuid":
				census.identities[0].filesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			if got, err := reviewRegisteredPolicyVolumes(policy, active, census); err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredPolicyVolumeReview{}) {
				t.Fatal("empty desired subset hid invalid whole evidence")
			}
		})
	}
}

func TestRegistryPolicyReviewEmptyAndFullLogicalIDBounds(t *testing.T) {
	census := collectMountedReviewFixture(t, nil)
	volume := shareconfig.Volume{ID: "explicit-books", FilesystemUUID: mountedReviewUUID}
	snapshot := registeredReviewFixture(t, volume)
	got, err := reviewRegisteredPolicyVolumes(registryPolicyFixture(), snapshot, census)
	if err != nil || got.volumes == nil || len(got.volumes) != 0 || got.registeredCount != 1 || got.unreferencedRegisteredCount != 1 || got.objectCount != 1 {
		t.Fatal("empty policy hid unreferenced registered backing")
	}
	volumes := []shareconfig.Volume{}
	for i := 0; i < shareconfig.MaxVolumes; i++ {
		volumes = append(volumes, shareconfig.Volume{ID: shareconfig.VolumeID(fmt.Sprintf("explicit-%d", i)), FilesystemUUID: shareconfig.FilesystemUUID(fmt.Sprintf("%08x-2222-3333-4444-555555555555", i+1))})
	}
	got, err = reviewRegisteredPolicyVolumes(registryPolicyFixture(volumes...), registeredReviewFixture(t, volumes...), census)
	if err != nil || len(got.volumes) != shareconfig.MaxVolumes || got.registeredCount != shareconfig.MaxVolumes || got.unreferencedRegisteredCount != 0 {
		t.Fatal("full logical-ID bound refused")
	}
	for _, observed := range got.volumes {
		if observed.observed.status != "not-observed-in-scope" {
			t.Fatal("missing scoped backing marked present")
		}
	}
}

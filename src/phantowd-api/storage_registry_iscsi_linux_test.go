//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func registryISCSIPolicyFixture(volumes ...shareconfig.Volume) iscsipolicy.Policy {
	p := iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 3, VolumeRevision: 7,
		Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}
	for i, volume := range volumes {
		group := i / iscsipolicy.MaxLUNs
		if i%iscsipolicy.MaxLUNs == 0 {
			p.Targets = append(p.Targets, iscsipolicy.Target{ID: iscsipolicy.TargetID(fmt.Sprintf("target-%d", group)),
				Name: fmt.Sprintf("iqn.2001-04.com.example:target-%d", group), State: "disabled", LUNs: []iscsipolicy.LUN{},
				Initiators: []iscsipolicy.Initiator{{Name: fmt.Sprintf("iqn.2001-04.com.example:peer-%d", group),
					Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "fixture-peer",
						InitiatorSecretRef: iscsipolicy.SecretRef(fmt.Sprintf("fixture-secret-%d", group))}, Grants: []iscsipolicy.Grant{}}}})
		}
		id := fmt.Sprintf("backing-%02d", i)
		lunID := iscsipolicy.LUNID(fmt.Sprintf("lun-%02d", i))
		p.Backings = append(p.Backings, iscsipolicy.Backing{ID: iscsipolicy.BackingID(id), VolumeID: volume.ID,
			RelativePath: "luns/" + id + ".img", CapacityBytes: 1 << 20, BlockSize: 512, Allocation: "preallocated"})
		p.Targets[group].LUNs = append(p.Targets[group].LUNs, iscsipolicy.LUN{ID: lunID, Number: uint16(i % iscsipolicy.MaxLUNs), BackingID: iscsipolicy.BackingID(id), Access: "ro"})
		p.Targets[group].Initiators[0].Grants = append(p.Targets[group].Initiators[0].Grants, iscsipolicy.Grant{LUNID: lunID, Access: "ro"})
	}
	return p
}

func TestRegisteredISCSIReviewSharedVolumeBoundedOwnedAndPrivate(t *testing.T) {
	volume := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
	unused := shareconfig.Volume{ID: "unused", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}
	config := registryPolicyFixture(volume, unused)
	snapshot := registeredReviewFixture(t, volume, unused)
	census := registryMDBackingFixture(t, "md-device")
	for _, count := range []int{0, 1, iscsipolicy.MaxBackings} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			volumes := make([]shareconfig.Volume, count)
			for i := range volumes {
				volumes[i] = volume
			}
			p := registryISCSIPolicyFixture(volumes...)
			before, _ := json.Marshal(p)
			got, err := reviewRegisteredISCSIVolumes(p, config, snapshot, census)
			unreferenced := 1
			if count == 0 {
				unreferenced = 2
			}
			if err != nil || got.policyRevision != 3 || got.volumeRevision != 7 || got.registryRevision != 11 ||
				got.coverage != census.coverage || got.objectCount != 1 || got.unclaimedObjectCount != 0 ||
				got.unreferencedRegisteredCount != unreferenced || got.backings == nil || len(got.backings) != count {
				t.Fatal("lost independent revisions, distinct volume references or whole census", got, err)
			}
			for _, b := range got.backings {
				if b.observed.status != "observed-in-scope" || b.observed.volumeID != volume.ID || b.kind != "md-device" || b.physicalDiskCount != 2 || b.mdArrayCount != 1 {
					t.Fatal("lost actual scoped MD topology", b)
				}
			}
			after, _ := json.Marshal(p)
			if string(before) != string(after) {
				t.Fatal("mutated desired model")
			}
			for i, j := 0, len(p.Backings)-1; i < j; i, j = i+1, j-1 {
				p.Backings[i], p.Backings[j] = p.Backings[j], p.Backings[i]
			}
			reordered, err := reviewRegisteredISCSIVolumes(p, config, snapshot, census)
			if err != nil || !reflect.DeepEqual(got, reordered) {
				t.Fatal("input order affected review")
			}
			if len(got.backings) != 0 {
				got.backings[0].kind = "caller-changed"
				fresh, err := reviewRegisteredISCSIVolumes(p, config, snapshot, census)
				if err != nil || !reflect.DeepEqual(fresh, reordered) {
					t.Fatal("result borrowed mutable storage")
				}
			}
			if _, err := json.Marshal(got); err == nil {
				t.Fatal("private review serialized")
			}
			if json.Unmarshal([]byte(`{}`), &got) == nil {
				t.Fatal("request constructed private review")
			}
		})
	}
}

func TestRegisteredISCSIReviewPathAdvisoriesAreVolumeScopedAndNotAdmission(t *testing.T) {
	volume := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
	other := shareconfig.Volume{ID: "other", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}
	snapshot := registeredReviewFixture(t, volume, other)
	census := collectMountedReviewFixture(t, nil)
	for _, tc := range []struct {
		path    string
		overlap bool
	}{
		{".", true}, {"luns", true}, {"luns/backing-00.img", true}, {"luns/backing-00.img/nested", true},
		{"luns/backing-00.img-other", false}, {"luns-other", false}, {"luns/other.img", false}, {"audio", false},
	} {
		for _, sameVolume := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", tc.path, sameVolume), func(t *testing.T) {
				config := registryPolicyFixture(volume, other)
				shareVolume := other.ID
				if sameVolume {
					shareVolume = volume.ID
				}
				config.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
				config.Shares.Shares = []shareconfig.Share{{ID: "books-share", Name: "Books", VolumeID: shareVolume, RelativePath: tc.path, Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
				config.NFS.Exports = []nfsconfig.Export{{ID: "11111111-2222-3333-4444-555555555555", VolumeID: shareVolume, RelativePath: tc.path,
					Clients: []nfsconfig.Client{{Network: "192.0.2.0/24", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
				got, err := reviewRegisteredISCSIVolumes(registryISCSIPolicyFixture(volume), config, snapshot, census)
				want := 0
				if sameVolume && tc.overlap {
					want = 1
				}
				if err != nil || len(got.backings) != 1 || got.backings[0].smbPathOverlapCount != want || got.backings[0].nfsPathOverlapCount != want || got.backings[0].observed.status != "observed-in-scope" {
					t.Fatal("RO exposure hidden, cross-volume path matched or advisory promoted to refusal", got, err)
				}
			})
		}
	}
}

func TestRegisteredISCSIReviewNeverRebindsUnknownConflictingMissingOrClonedVolume(t *testing.T) {
	for _, kind := range []string{"unknown", "conflict", "missing", "clone", "alias", "unresolved"} {
		t.Run(kind, func(t *testing.T) {
			census := collectMountedReviewFixture(t, func(sysfs, proc fstest.MapFS, roots *mountguard.MountedInventory) {
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
					roots.ConflictingUUIDs = []string{mountedReviewUUID}
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:16 / /other ro - ext4 /dev/sdb ro\n")...)
				} else {
					proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 8:1 / /other ro - ext4 /dev/sda1 ro\n")...)
				}
				roots.Mounts = append(roots.Mounts, alias)
			})
			registered := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
			if kind == "missing" {
				registered.FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			desired := registered
			status := "observed-in-scope"
			switch kind {
			case "unknown":
				desired.ID = "different-id"
				status = "not-registered"
			case "conflict":
				desired.FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
				status = "registry-policy-conflict"
			case "missing":
				status = "not-observed-in-scope"
			case "clone":
				status = "ambiguous-in-scope"
			}
			got, err := reviewRegisteredISCSIVolumes(registryISCSIPolicyFixture(desired), registryPolicyFixture(desired), registeredReviewFixture(t, registered), census)
			if err != nil || len(got.backings) != 1 || got.backings[0].observed.status != status {
				t.Fatal("lost status", got, err)
			}
			b := got.backings[0]
			if status != "observed-in-scope" {
				if b.kind != "" || b.physicalDiskCount != 0 || b.mdArrayCount != 0 {
					t.Fatal("nonunique claim selected actual topology", b)
				}
			} else if b.kind != "physical-partition" || b.physicalDiskCount != 1 || b.observed.scopedDiskEvidenceUnresolved != (kind == "unresolved") {
				t.Fatal("lost scoped unresolved evidence", b)
			}
			if kind == "alias" && (b.observed.objectCount != 1 || b.observed.aliasCount != 2) {
				t.Fatal("alias inflated objects")
			}
			if kind == "clone" && b.observed.objectCount != 2 {
				t.Fatal("clone hidden")
			}
			if (kind == "unknown" || kind == "conflict") && (b.observed.objectCount != 0 || b.observed.aliasCount != 0) {
				t.Fatal("foreign observation leaked")
			}
		})
	}
}

func TestRegisteredISCSIReviewWholeEvidenceRequiredEvenWithoutLUNs(t *testing.T) {
	snapshot := registeredReviewFixture(t)
	for _, kind := range []string{"zero-policy", "stale-volume-revision", "nil-backings", "split-shares", "split-nfs", "zero-snapshot", "storage", "roots", "coverage", "identity", "arrays"} {
		t.Run(kind, func(t *testing.T) {
			p, config, active := registryISCSIPolicyFixture(), registryPolicyFixture(), snapshot
			census := registryMDBackingFixture(t, "md-device")
			switch kind {
			case "zero-policy":
				p = iscsipolicy.Policy{}
			case "stale-volume-revision":
				p.VolumeRevision++
			case "nil-backings":
				p.Backings = nil
			case "split-shares":
				config.Shares.Revision++
			case "split-nfs":
				config.NFS.Revision++
			case "zero-snapshot":
				active = volumeregistry.Snapshot{}
			case "storage":
				census.storage.collectionComplete = false
			case "roots":
				census.roots.Mounts = nil
			case "coverage":
				census.coverage.mountCount++
			case "identity":
				census.identities[0].filesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "arrays":
				census.arrays = nil
			}
			got, err := reviewRegisteredISCSIVolumes(p, config, active, census)
			if err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredISCSIVolumeReview{}) {
				t.Fatal("invalid whole evidence escaped empty subset", got, err)
			}
		})
	}
}

func TestRegisteredISCSICollectorOneBracketAndNoPartialDrift(t *testing.T) {
	for _, kind := range []string{"stable", "invalid-policy", "stale-policy", "registry-aba", "directory-aba", "root-drift", "excluded-mount", "unclaimed-disk", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			volume := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
			r, file, data := registryCollectorReader(t, volume)
			p := registryISCSIPolicyFixture(volume)
			if kind == "invalid-policy" {
				p.Format = "invalid"
			}
			if kind == "stale-policy" {
				p.VolumeRevision++
			}
			sysfs, proc, roots := mountedCensusFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			got, err := collectRegisteredStorageReviewScope(ctx, registryPolicyFixture(volume), &p, r, sysfs, proc,
				func(anchors []string) (mountguard.MountedInventory, error) {
					calls++
					if !reflect.DeepEqual(anchors, []string{"/data"}) {
						t.Fatal("subset census")
					}
					if calls == 3 {
						switch kind {
						case "registry-aba":
							if os.WriteFile(file, []byte(`{}`), 0600) != nil || os.WriteFile(file, data, 0600) != nil {
								t.Fatal("fixture restore failed")
							}
						case "directory-aba":
							other := filepath.Join(filepath.Dir(file), "temporary")
							if os.WriteFile(other, []byte("fixture"), 0600) != nil || os.Remove(other) != nil {
								t.Fatal("fixture directory restore failed")
							}
						case "root-drift":
							roots.Mounts[0].MountID++
						case "cancel":
							cancel()
						}
					}
					if calls == 2 && kind == "excluded-mount" {
						proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 0:44 / /extra ro - tmpfs tmpfs ro\n")...)
					}
					if calls == 2 && kind == "unclaimed-disk" {
						addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "other-physical-disk", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
						physicalizeBlockNode(sysfs, "sdb")
					}
					return roots, nil
				})
			if kind == "stable" {
				if err != nil || calls != 4 || len(got.iscsi.backings) != 1 || got.iscsi.policyRevision != 3 || got.iscsi.volumeRevision != 7 || got.iscsi.registryRevision != 11 || got.iscsi.coverage != got.policy.coverage || got.iscsi.coverage != got.backing.coverage || got.iscsi.backings[0].kind != "physical-partition" {
					t.Fatal("independent census or partial composite", got, calls, err)
				}
			} else if err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredStorageReview{}) {
				t.Fatal("drift leaked composite", got, calls, err)
			}
			if (kind == "invalid-policy" || kind == "stale-policy") && calls != 0 {
				t.Fatal("invalid policy reached observer")
			}
		})
	}
}

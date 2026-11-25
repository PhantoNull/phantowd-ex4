// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"os"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestMatchRegisteredStorageRequiresExactClaimsAndBacking(t *testing.T) {
	ctx := context.Background()
	reader, _, _ := registryCollectorReader(t, shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID})
	snapshot, err := reader.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	census := collectMountedReviewFixture(t, nil)
	identity := census.identities[0]
	disk := identity.physicalDisks[0]
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	valid := registeredStorageGrant{mount: mountowner.LinuxVolumeGrant{
		VolumeID: "books", SourcePath: identity.anchor, Source: file,
		Expected: mountguard.Expected{MountID: identity.mountID, DeviceMajor: identity.sourceMajor,
			DeviceMinor: identity.sourceMinor, FilesystemUUID: mountedReviewUUID},
	}, disks: []registeredDiskProof{{serial: disk.serialEvidence, wwn: disk.wwnEvidence}}}
	// This exercises census reconciliation only. The Linux mount owner validates
	// the real descriptor after the match and before the first bind.
	if grants, err := matchRegisteredStorage(snapshot, census, []registeredStorageGrant{valid}); err != nil || len(grants) != 1 || grants[0] != valid.mount {
		t.Fatal("independent matching grant was not passed through", err)
	}
	for name, change := range map[string]func(*registeredStorageGrant){
		"mount":  func(bad *registeredStorageGrant) { bad.mount.Expected.MountID++ },
		"path":   func(bad *registeredStorageGrant) { bad.mount.SourcePath = "/other" },
		"device": func(bad *registeredStorageGrant) { bad.mount.Expected.DeviceMinor++ },
		"id":     func(bad *registeredStorageGrant) { bad.mount.VolumeID = "other" },
		"uuid": func(bad *registeredStorageGrant) {
			bad.mount.Expected.FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
		},
		"disk": func(bad *registeredStorageGrant) { bad.disks = []registeredDiskProof{{wwn: [32]byte{1}}} },
		"array": func(bad *registeredStorageGrant) {
			bad.arrays = []registeredMDProof{{uuid: mountedReviewUUID, level: "raid1"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			change(&changed)
			if grants, err := matchRegisteredStorage(snapshot, census, []registeredStorageGrant{changed}); err == nil || grants != nil {
				t.Fatal("mismatched grant produced authority")
			}
		})
	}
	aliased := collectMountedReviewFixture(t, func(_ fstest.MapFS, proc fstest.MapFS, roots *mountguard.MountedInventory) {
		proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, "41 36 8:1 / /data-alias ro - ext4 /dev/sda1 ro\n"...)
		alias := roots.Mounts[0]
		alias.Anchor, alias.MountID = "/data-alias", 70002
		roots.Mounts = append(roots.Mounts, alias)
	})
	if grants, err := matchRegisteredStorage(snapshot, aliased, []registeredStorageGrant{valid}); err == nil || grants != nil {
		t.Fatal("a second source alias produced authority")
	}
	if !registeredStorageCensusUnchanged(census, census, nil) || registeredStorageCensusUnchanged(census, aliased, nil) {
		t.Fatal("post-bind reconciliation accepted an undeclared mount")
	}
}

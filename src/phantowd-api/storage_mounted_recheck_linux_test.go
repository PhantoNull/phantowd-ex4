//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

func TestMountedExtCensusRecheckStableCompleteScope(t *testing.T) {
	sysfs, proc, roots := mountedCensusFixture()
	previous, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc,
		func([]string) (mountguard.MountedInventory, error) { return roots, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Timestamps are observations, not mount/device identities. Input order is
	// normalized by the complete collector, not used as a freshness signal.
	previous.mounts.ObservedAt = time.Unix(1, 0).UTC()
	lines := strings.Split(strings.TrimSuffix(censusFixtureMounts, "\n"), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	proc["self/mountinfo"].Data = []byte(strings.Join(lines, "\n") + "\n")
	calls := 0
	if err := recheckTrustedMountedExtCensusWith(context.Background(), previous, sysfs, proc,
		func(anchors []string) (mountguard.MountedInventory, error) {
			calls++
			if !reflect.DeepEqual(anchors, []string{"/data"}) {
				t.Fatal("recheck accepted a caller-selected subset", anchors)
			}
			return roots, nil
		}); err != nil || calls != 2 {
		t.Fatal("unchanged complete scope refused", err, calls)
	}
}

func TestMountedExtCensusRecheckRefusesInvalidPriorBeforeRootIO(t *testing.T) {
	for _, scenario := range []string{"zero", "coverage", "mounts incomplete", "storage incomplete", "nil arrays",
		"nil roots", "nil conflicts", "derived UUID", "derived mount ID", "missing identity"} {
		t.Run(scenario, func(t *testing.T) {
			sysfs, proc, _ := mountedCensusFixture()
			previous := collectMountedReviewFixture(t, nil)
			switch scenario {
			case "zero":
				previous = trustedMountedExtCensus{}
			case "coverage":
				previous.coverage.processRootExcluded++
			case "mounts incomplete":
				previous.mounts.collectionComplete = false
			case "storage incomplete":
				previous.storage.collectionComplete = false
			case "nil arrays":
				previous.arrays = nil
			case "nil roots":
				previous.roots.Mounts = nil
			case "nil conflicts":
				previous.roots.ConflictingUUIDs = nil
			case "derived UUID":
				previous.identities[0].filesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "derived mount ID":
				previous.identities[0].mountID++
			case "missing identity":
				previous.identities = []mountedStorageIdentity{}
			}
			err := recheckTrustedMountedExtCensusWith(context.Background(), previous, sysfs, proc,
				func([]string) (mountguard.MountedInventory, error) {
					t.Fatal("invalid previous census performed root I/O")
					return mountguard.MountedInventory{}, nil
				})
			if !errors.Is(err, errMountedStorageIdentityIncomplete) {
				t.Fatal("invalid prior did not return redacted incomplete error", err)
			}
		})
	}
}

func TestMountedExtCensusRecheckDetectsChangesAcrossEntireScope(t *testing.T) {
	for _, scenario := range []string{"UUID", "unique mount ID", "mountinfo ID", "mount mode", "subtree", "new alias",
		"removed root", "excluded subtree", "excluded filesystem", "disk generation", "disk VPD",
		"mounts unavailable", "mdstat unavailable", "sysfs unavailable", "first observer fails", "second observer fails",
		"second root drifts", "cancelled during observation"} {
		t.Run(scenario, func(t *testing.T) {
			sysfs, proc, roots := mountedCensusFixture()
			previous, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc,
				func([]string) (mountguard.MountedInventory, error) { return roots, nil })
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "UUID":
				roots.Mounts[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			case "unique mount ID":
				roots.Mounts[0].MountID++
			case "mountinfo ID":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "38 36", "98 36", 1))
			case "mount mode":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "/data ro", "/data rw", 1))
			case "subtree":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "8:1 / /data", "8:1 /new-subtree /data", 1))
				roots.Mounts = []mountguard.MountedIdentity{}
			case "new alias":
				proc["self/mountinfo"].Data = []byte(censusFixtureMounts + "41 36 8:1 / /new-alias ro - ext4 /dev/sda1 ro\n")
				alias := roots.Mounts[0]
				alias.Anchor, alias.MountID = "/new-alias", 70002
				roots.Mounts = append(roots.Mounts, alias)
			case "removed root":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "38 36 8:1 / /data ro - ext4 /dev/sda1 ro\n", "", 1))
				roots.Mounts = []mountguard.MountedIdentity{}
			case "excluded subtree":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "/books /books", "/different /books", 1))
			case "excluded filesystem":
				proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "- xfs", "- btrfs", 1))
			case "disk generation":
				sysfs["devices/pci0000:00/block/sda/diskseq"].Data = []byte("99\n")
			case "disk VPD":
				data := sysfs["devices/pci0000:00/block/sda/device/vpd_pg80"].Data
				data[len(data)-1] ^= 1
			case "mounts unavailable":
				delete(proc, "self/mountinfo")
			case "mdstat unavailable":
				delete(proc, "mdstat")
			case "sysfs unavailable":
				delete(sysfs, "devices/pci0000:00/block/sda/diskseq")
			}
			calls := 0
			err = recheckTrustedMountedExtCensusWith(ctx, previous, sysfs, proc,
				func([]string) (mountguard.MountedInventory, error) {
					calls++
					if (scenario == "first observer fails" && calls == 1) || (scenario == "second observer fails" && calls == 2) {
						return mountguard.MountedInventory{}, errors.New("fixture-private-detail")
					}
					if scenario == "second root drifts" && calls == 2 {
						roots.Mounts[0].MountID++
					}
					if scenario == "cancelled during observation" {
						cancel()
					}
					return roots, nil
				})
			if !errors.Is(err, errMountedStorageIdentityIncomplete) || err.Error() != errMountedStorageIdentityIncomplete.Error() {
				t.Fatal("changed/incomplete scope was accepted or detail leaked", err)
			}
		})
	}
}

func TestMountedExtCensusRecheckInvalidConstruction(t *testing.T) {
	previous := collectMountedReviewFixture(t, nil)
	for _, scenario := range []string{"nil context", "cancelled", "nil sysfs", "nil proc", "nil observer"} {
		t.Run(scenario, func(t *testing.T) {
			sysfs, proc, _ := mountedCensusFixture()
			ctx := context.Background()
			observer := mountedExtRootObserver(func([]string) (mountguard.MountedInventory, error) {
				t.Fatal("invalid construction performed root I/O")
				return mountguard.MountedInventory{}, nil
			})
			switch scenario {
			case "nil context":
				ctx = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "nil sysfs":
				sysfs = nil
			case "nil proc":
				proc = nil
			case "nil observer":
				observer = nil
			}
			if err := recheckTrustedMountedExtCensusWith(ctx, previous, sysfs, proc, observer); !errors.Is(err, errMountedStorageIdentityIncomplete) {
				t.Fatal("invalid construction was accepted", err)
			}
		})
	}
}

func TestMountedExtCensusRecheckEmptyAndRootBudget(t *testing.T) {
	for _, count := range []int{0, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			sysfs, proc, roots := mountedCensusFixture()
			var mounts strings.Builder
			fmt.Fprint(&mounts, "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
			roots.Mounts = []mountguard.MountedIdentity{}
			for i := 0; i < count; i++ {
				anchor := fmt.Sprintf("/data%02d", i)
				fmt.Fprintf(&mounts, "%d 1 8:1 / %s ro - ext4 /dev/sda1 ro\n", i+2, anchor)
				roots.Mounts = append(roots.Mounts, mountguard.MountedIdentity{Anchor: anchor, FilesystemUUID: mountedReviewUUID,
					MountID: uint64(i + 1), DeviceMajor: 8, DeviceMinor: 1})
			}
			proc["self/mountinfo"].Data = []byte(mounts.String())
			observer := func(anchors []string) (mountguard.MountedInventory, error) {
				if count == 0 || len(anchors) != count {
					t.Fatal("incorrect observation budget", anchors)
				}
				return roots, nil
			}
			previous, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc, observer)
			if err != nil {
				t.Fatal(err)
			}
			if err := recheckTrustedMountedExtCensusWith(context.Background(), previous, sysfs, proc, observer); err != nil {
				t.Fatal("unchanged empty/exact-budget scope refused", err)
			}
			// Even excluded entries belong to the full snapshot and must not
			// disappear just because there are no current desired volumes.
			proc["self/mountinfo"].Data = []byte(mounts.String() + "90 1 0:42 / /new-proc ro - proc proc ro\n")
			if err := recheckTrustedMountedExtCensusWith(context.Background(), previous, sysfs, proc, observer); !errors.Is(err, errMountedStorageIdentityIncomplete) {
				t.Fatal("changed complete scope was accepted", err)
			}
		})
	}
}

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
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

const censusFixtureMounts = "36 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
	"37 36 0:42 / /proc ro - proc proc ro\n" +
	"38 36 8:1 / /data ro - ext4 /dev/sda1 ro\n" +
	"39 36 8:1 /books /books ro - ext4 /dev/sda1 ro\n" +
	"40 36 8:0 / /unsupported ro - xfs /dev/sda ro\n"

func mountedCensusFixture() (fstest.MapFS, fstest.MapFS, mountguard.MountedInventory) {
	sysfs := fixtureSysfs()
	physicalizeBlockNode(sysfs, "sda")
	proc := discoveryProc(censusFixtureMounts, emptySwaps)
	proc["mdstat"] = &fstest.MapFile{Data: []byte("Personalities : [raid1]\nunused devices: <none>\n")}
	return sysfs, proc, mountguard.MountedInventory{Mounts: []mountguard.MountedIdentity{{
		Anchor: "/data", FilesystemUUID: "66666666-7777-8888-9999-aaaaaaaaaaaa", MountID: 70001, DeviceMajor: 8, DeviceMinor: 1,
	}}, ConflictingUUIDs: []string{}}
}

func TestMountedExtCensusDerivesCompleteScopedAnchors(t *testing.T) {
	sysfs, proc, roots := mountedCensusFixture()
	calls := 0
	observed, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc,
		func(anchors []string) (mountguard.MountedInventory, error) {
			calls++
			if !reflect.DeepEqual(anchors, []string{"/data"}) {
				t.Fatalf("caller subset/excluded mount reached root observer: %q", anchors)
			}
			return roots, nil
		})
	if err != nil || calls != 2 || len(observed.identities) != 1 || observed.identities[0].sourceName != "sda1" ||
		observed.identities[0].filesystemUUIDConflict || observed.identities[0].mountID != 70001 ||
		len(observed.identities[0].physicalDisks) != 1 {
		t.Fatalf("scoped census = %+v, calls=%d, err=%v", observed, calls, err)
	}
	want := mountedExtCensusCoverage{mountCount: 5, observedRootCount: 1, processRootExcluded: 1,
		subtreeExcluded: 1, unsupportedFilesystemExcluded: 1, zeroMajorExcluded: 1}
	if observed.coverage != want || !observed.mounts.collectionComplete || !observed.storage.collectionComplete {
		t.Fatalf("coverage/completeness incorrectly implied: %+v", observed.coverage)
	}
	if _, err := json.Marshal(observed); err == nil {
		t.Fatal("private census could be serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &observed); err == nil {
		t.Fatal("untrusted JSON could create census evidence")
	}
}

func TestMountedExtCensusEmptyScopeIsNotUnreadable(t *testing.T) {
	sysfs, proc, _ := mountedCensusFixture()
	proc["self/mountinfo"].Data = []byte("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
	observed, err := collectTrustedMountedExtCensusWith(context.Background(), sysfs, proc,
		func([]string) (mountguard.MountedInventory, error) {
			t.Fatal("empty scope opened a root")
			return mountguard.MountedInventory{}, nil
		})
	if err != nil || observed.identities == nil || len(observed.identities) != 0 || observed.coverage.processRootExcluded != 1 {
		t.Fatal("empty completed scope confused with unavailable evidence", observed, err)
	}
}

func TestMountedExtCensusRefusesEveryUncertainObservation(t *testing.T) {
	for _, scenario := range []string{"first failure", "second failure", "first nil", "missing root", "extra root", "wrong anchor",
		"wrong device", "invalid UUID", "unique ID changed", "UUID changed", "reused buffer changed", "mountinfo ID changed",
		"filesystem root changed", "storage generation changed", "storage VPD changed", "mounts unreadable", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			sysfs, proc, roots := mountedCensusFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			observed, err := collectTrustedMountedExtCensusWith(ctx, sysfs, proc,
				func([]string) (mountguard.MountedInventory, error) {
					calls++
					if calls == 1 {
						switch scenario {
						case "first failure":
							return mountguard.MountedInventory{}, errors.New("fixture")
						case "first nil":
							return mountguard.MountedInventory{}, nil
						case "missing root":
							roots.Mounts = []mountguard.MountedIdentity{}
						case "extra root":
							roots.Mounts = append(roots.Mounts, roots.Mounts[0])
						case "wrong anchor":
							roots.Mounts[0].Anchor = "/unrequested"
						case "wrong device":
							roots.Mounts[0].DeviceMinor++
						case "invalid UUID":
							roots.Mounts[0].FilesystemUUID = "unknown"
						case "cancelled":
							cancel()
						}
					} else {
						switch scenario {
						case "second failure":
							return mountguard.MountedInventory{}, errors.New("fixture")
						case "unique ID changed", "reused buffer changed":
							roots.Mounts[0].MountID++
						case "UUID changed":
							roots.Mounts[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
						case "mountinfo ID changed":
							proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "38 36", "98 36", 1))
						case "filesystem root changed":
							proc["self/mountinfo"].Data = []byte(strings.Replace(censusFixtureMounts, "8:1 / /data", "8:1 /subtree /data", 1))
						case "storage generation changed":
							sysfs["devices/pci0000:00/block/sda/diskseq"].Data = []byte("99\n")
						case "storage VPD changed":
							sysfs["devices/pci0000:00/block/sda/device/vpd_pg80"].Data[len(sysfs["devices/pci0000:00/block/sda/device/vpd_pg80"].Data)-1] ^= 1
						case "mounts unreadable":
							delete(proc, "self/mountinfo")
						}
					}
					return roots, nil
				})
			if !errors.Is(err, errMountedStorageIdentityIncomplete) || !reflect.DeepEqual(observed, trustedMountedExtCensus{}) {
				t.Fatalf("uncertain/partial census escaped: %+v, %v", observed, err)
			}
		})
	}
}

func TestMountedExtCensusRefusesInvalidConstruction(t *testing.T) {
	sysfs, proc, _ := mountedCensusFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, scenario := range []string{"nil context", "cancelled", "nil sysfs", "nil proc", "nil observer"} {
		t.Run(scenario, func(t *testing.T) {
			currentCtx, currentSys, currentProc := context.Background(), sysfs, proc
			observer := mountedExtRootObserver(func([]string) (mountguard.MountedInventory, error) {
				t.Fatal("invalid inputs opened roots")
				return mountguard.MountedInventory{}, nil
			})
			switch scenario {
			case "nil context":
				currentCtx = nil
			case "cancelled":
				currentCtx = ctx
			case "nil sysfs":
				currentSys = nil
			case "nil proc":
				currentProc = nil
			case "nil observer":
				observer = nil
			}
			if got, err := collectTrustedMountedExtCensusWith(currentCtx, currentSys, currentProc, observer); err == nil || !reflect.DeepEqual(got, trustedMountedExtCensus{}) {
				t.Fatal("invalid construction returned evidence", got, err)
			}
		})
	}
}

func TestMountedExtCensusPlanBoundsAndAmbiguity(t *testing.T) {
	sysfs, _, _ := mountedCensusFixture()
	storage, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	read := func(data string) mountSnapshot {
		t.Helper()
		got, err := collectMountInventory(fstest.MapFS{"self/mountinfo": {Data: []byte(data)}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, data := range []string{
		"36 0 99:99 / /unknown ro - ext4 /dev/unknown ro\n",
		"36 0 8:1 / /data ro - ext4 /dev/sda1 ro\n37 36 8:1 / /data ro - ext4 /dev/sda1 ro\n",
		"36 0 8:1 / /noncanonical/../data ro - ext4 /dev/sda1 ro\n",
	} {
		if roots, _, err := planMountedExtCensus(storage, read(data)); err == nil || roots != nil {
			t.Fatal("orphan, overmount or noncanonical path admitted", roots, err)
		}
	}
	var data strings.Builder
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&data, "%d 0 8:1 / /data%d ro - ext4 /dev/sda1 ro\n", i+1, i)
	}
	roots, coverage, err := planMountedExtCensus(storage, read(data.String()))
	if err != nil || len(roots) != 64 || coverage.observedRootCount != 64 {
		t.Fatal("exact root budget refused", err)
	}
	fmt.Fprint(&data, "65 0 8:1 / /data64 ro - ext4 /dev/sda1 ro\n")
	if roots, _, err := planMountedExtCensus(storage, read(data.String())); err == nil || roots != nil {
		t.Fatal("partial census escaped budget", roots, err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestPlanTrustedStorageDiscoverySelectsCompleteUnmountedLeafSet(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	storage, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := collectMountInventory(discoveryProc("36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n", emptySwaps), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planTrustedStorageDiscovery(storage, mounts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 2 || plan.Candidates[0].Name != "sdb" || plan.Candidates[1].Name != "sdc" {
		t.Fatalf("expected the complete two-disk leaf candidate set, got %+v", plan.Candidates)
	}
	if !plan.HasAmbiguousIdentity || plan.IdentityEvidenceIncomplete {
		t.Fatalf("duplicate valid VPD identities must remain explicitly ambiguous, not unique/incomplete: %+v", plan)
	}
	for _, candidate := range plan.Candidates {
		if candidate.SerialStatus != identityAmbiguous || candidate.WWNStatus != identityAmbiguous {
			t.Fatalf("ambiguous candidate lost its identity state: %+v", candidate)
		}
	}
	wantExcluded := map[string]string{
		"sda": "visible-dependent-mount", "sdd": "removable-device",
		"sde": "member-of-stacked-block-node", "md0": "virtual-block-node", "sdf": "virtual-block-node",
	}
	if len(plan.Excluded) != len(wantExcluded) {
		t.Fatalf("unexpected excluded-node set: %+v", plan.Excluded)
	}
	for _, excluded := range plan.Excluded {
		if wantExcluded[excluded.Name] != excluded.Reason {
			t.Fatalf("unexpected exclusion: %+v; all=%+v", excluded, plan.Excluded)
		}
		delete(wantExcluded, excluded.Name)
	}
	if len(wantExcluded) != 0 {
		t.Fatalf("missing exclusions: %+v", wantExcluded)
	}
}

func TestPlanTrustedStorageDiscoveryRequiresPrivateCompleteSnapshots(t *testing.T) {
	storage, err := collectStorage(fixtureDiscoverySysfs())
	if err != nil {
		t.Fatal(err)
	}
	proc := discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", emptySwaps)
	mounts, err := collectMountInventory(proc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(mounts)
	if err != nil {
		t.Fatal(err)
	}
	var decodedMounts mountSnapshot
	if err := json.Unmarshal(encoded, &decodedMounts); err != nil {
		t.Fatal(err)
	}
	if _, err := planTrustedStorageDiscovery(storage, decodedMounts); !errors.Is(err, errStorageDiscoveryIncomplete) {
		t.Fatalf("serialized mount snapshot was accepted as trusted: %v", err)
	}
	storage.collectionComplete = false
	if _, err := planTrustedStorageDiscovery(storage, mounts); !errors.Is(err, errStorageDiscoveryIncomplete) {
		t.Fatalf("unsealed storage snapshot was accepted as trusted: %v", err)
	}
}

func TestPlanTrustedStorageDiscoveryRefusesUnsupportedMultiDeviceFilesystems(t *testing.T) {
	for _, filesystem := range []string{"btrfs", "bcachefs", "zfs"} {
		t.Run(filesystem, func(t *testing.T) {
			proc := discoveryProc(
				"36 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
					"37 36 8:16 / /pool rw - "+filesystem+" /dev/sdb rw\n",
				emptySwaps,
			)
			called := false
			_, err := discoverTrustedStorageWith(fixtureDiscoverySysfs(), proc, func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
				called = true
				return nil, nil
			})
			if !errors.Is(err, errStorageDiscoveryIncomplete) || called {
				t.Fatalf("mounted multi-device filesystem must refuse discovery before opening: err=%v opener=%v", err, called)
			}
		})
	}
}

func TestDiscoverTrustedStorageOpensAndRechecksTheWholeCandidateSet(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	proc := discoveryProc("36 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n", emptySwaps)
	var requested []string
	var opened []*os.File
	discovery, err := discoverTrustedStorageWith(sysfs, proc, func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		requested = make([]string, len(devices))
		sources := make([]volumeprobe.BlockDeviceSource, 0, len(devices))
		for index, device := range devices {
			requested[index] = device.Name
			file, err := os.CreateTemp(t.TempDir(), "storage-source-")
			if err != nil {
				return sources, err
			}
			opened = append(opened, file)
			sources = append(sources, volumeprobe.BlockDeviceSource{File: file, Generation: device.Generation})
		}
		// A broker/opener may return descriptors in a different order. The
		// trusted bridge restores collector inventory order before handoff.
		for left, right := 0, len(sources)-1; left < right; left, right = left+1, right-1 {
			sources[left], sources[right] = sources[right], sources[left]
		}
		return sources, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(requested, ",") != "sdb,sdc" || len(discovery.candidates) != 2 || len(discovery.sources) != 2 {
		discovery.Close()
		t.Fatalf("incomplete candidate set escaped the coordinator: request=%v candidates=%+v sources=%d", requested, discovery.candidates, len(discovery.sources))
	}
	for index, source := range discovery.sources {
		if source.Generation != discovery.candidates[index].Generation {
			discovery.Close()
			t.Fatalf("descriptor set was not returned in trusted inventory order: %+v", discovery.sources)
		}
	}
	if !discovery.inventory.collectionComplete || !discovery.mounts.collectionComplete {
		discovery.Close()
		t.Fatal("coordinator did not retain collector-produced inventories")
	}
	if err := discovery.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range opened {
		if _, err := file.Stat(); err == nil {
			t.Fatal("discovery close left an opened source descriptor")
		}
	}
}

func TestDiscoverTrustedStorageFailsClosedAndClosesPartialSources(t *testing.T) {
	t.Run("opener error", func(t *testing.T) {
		sysfs := fixtureDiscoverySysfs()
		proc := discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", emptySwaps)
		file, err := os.CreateTemp(t.TempDir(), "partial-source-")
		if err != nil {
			t.Fatal(err)
		}
		_, err = discoverTrustedStorageWith(sysfs, proc, func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
			return []volumeprobe.BlockDeviceSource{{File: file, Generation: devices[0].Generation}}, errors.New("private opener detail")
		})
		if !errors.Is(err, errStorageDiscoveryIncomplete) {
			t.Fatalf("opener failure was not redacted/incomplete: %v", err)
		}
		if _, statErr := file.Stat(); statErr == nil {
			t.Fatal("partial descriptor was not closed after opener failure")
		}
	})

	for _, name := range []string{"sysfs generation changed", "mount inventory changed"} {
		t.Run(name, func(t *testing.T) {
			sysfs := fixtureDiscoverySysfs()
			proc := discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", emptySwaps)
			var opened []*os.File
			_, err := discoverTrustedStorageWith(sysfs, proc, func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
				sources := make([]volumeprobe.BlockDeviceSource, 0, len(devices))
				for _, device := range devices {
					file, createErr := os.CreateTemp(t.TempDir(), "changed-source-")
					if createErr != nil {
						return sources, createErr
					}
					opened = append(opened, file)
					sources = append(sources, volumeprobe.BlockDeviceSource{File: file, Generation: device.Generation})
				}
				if name == "sysfs generation changed" {
					sysfs["devices/pci0000:00/block/sdb/diskseq"] = &fstest.MapFile{Data: []byte("18\n")}
				} else {
					proc["self/mountinfo"] = &fstest.MapFile{Data: []byte("36 0 8:16 / /rw rw - ext4 /dev/sdb rw\n")}
				}
				return sources, nil
			})
			if !errors.Is(err, errStorageDiscoveryIncomplete) {
				t.Fatalf("changed cross-snapshot state was accepted: %v", err)
			}
			for _, file := range opened {
				if _, statErr := file.Stat(); statErr == nil {
					t.Fatal("descriptor remained open after changed inventory")
				}
			}
		})
	}
}

func TestDiscoverTrustedStorageRefusesActiveOrMalformedSwapState(t *testing.T) {
	for _, swaps := range []string{
		"Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n",
		"Filename Type Size Used Priority\n/dev/sda2 partition unknown 0 -2\n",
		"not-the-proc-swaps-header\n",
	} {
		called := false
		_, err := discoverTrustedStorageWith(fixtureDiscoverySysfs(), discoveryProc("36 0 8:1 / / rw - ext4 /dev/sda1 rw\n", swaps), func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
			called = true
			return []volumeprobe.BlockDeviceSource{}, nil
		})
		if !errors.Is(err, errStorageDiscoveryIncomplete) || called {
			t.Fatalf("swap state must block the complete assessment before opening: err=%v opener=%v", err, called)
		}
	}
}

func fixtureDiscoverySysfs() fstest.MapFS {
	sysfs := fixtureSysfs()
	physicalizeBlockNode(sysfs, "sda")
	addPhysicalBlockNode(sysfs, "sdb", 8, 16, "duplicate-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	addPhysicalBlockNode(sysfs, "sdc", 8, 32, "duplicate-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	addPhysicalBlockNode(sysfs, "sdd", 8, 48, "removable-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 4})
	sysfs["devices/pci0000:00/block/sdd/removable"] = &fstest.MapFile{Data: []byte("1\n")}
	addPhysicalBlockNode(sysfs, "sde", 8, 64, "stack-member", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 5})
	addNonPartitionBlockNode(sysfs, "md0", 9, 0, "array", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 6})
	sysfs["devices/virtual/block/md0/diskseq"] = &fstest.MapFile{Data: []byte("90\n")}
	addSysfsBlockRelation(sysfs, "devices/pci0000:00/block/sde", "holders", "md0", "../../../../virtual/block/md0")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/md0", "slaves", "sde", "../../../../pci0000:00/block/sde")
	addNonPartitionBlockNode(sysfs, "sdf", 7, 0, "loop", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 7})
	return sysfs
}

func addPhysicalBlockNode(sysfs fstest.MapFS, name string, major, minor uint32, serial string, wwn []byte) {
	addNonPartitionBlockNode(sysfs, name, major, minor, serial, wwn)
	physicalizeBlockNode(sysfs, name)
}

func physicalizeBlockNode(sysfs fstest.MapFS, name string) {
	oldTarget := "devices/virtual/block/" + name
	newTarget := "devices/pci0000:00/block/" + name
	for filename, file := range sysfs {
		if filename == oldTarget || strings.HasPrefix(filename, oldTarget+"/") {
			sysfs[newTarget+strings.TrimPrefix(filename, oldTarget)] = file
			delete(sysfs, filename)
		}
	}
	for filename, file := range sysfs {
		if !strings.HasPrefix(filename, "class/block/") || file.Mode&fs.ModeSymlink == 0 {
			continue
		}
		target := strings.Replace(string(file.Data), "../../"+oldTarget, "../../"+newTarget, 1)
		if target != string(file.Data) {
			sysfs[filename] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
		}
	}
}

func discoveryProc(mountinfo, swaps string) fstest.MapFS {
	return fstest.MapFS{
		"self":           {Mode: fs.ModeDir | 0o555},
		"self/mountinfo": {Data: []byte(mountinfo)},
		"swaps":          {Data: []byte(swaps)},
	}
}

const emptySwaps = "Filename Type Size Used Priority\n"

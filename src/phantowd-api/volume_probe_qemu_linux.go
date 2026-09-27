//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// Fixed QEMU harness, not the production broker or arbitrary device opener.
func runProbeFixture(source *os.File) (volumeprobe.Result, error) {
	return volumeprobe.Inspect(context.Background(), source)
}

func probeQEMUUnmountedStorage() error {
	// The dispatcher already requires ARMv5 and exact Versatile PB model.
	if os.Geteuid() != 0 {
		return errors.New("QEMU probe requires fixture root")
	}
	if err := verifyQEMUNFSDevice(os.DirFS("/sys")); err != nil {
		return err
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sdc", qemuCloneSerial, qemuCloneWWN); err != nil {
		return err
	}
	discovery, err := discoverTrustedStorageWith(os.DirFS("/sys"), os.DirFS("/proc"), volumeprobe.OpenObservedBlockSources)
	if err != nil {
		return errors.New("complete QEMU trusted storage discovery was unavailable")
	}
	defer discovery.Close()
	initialInventory := discovery.inventory
	observedDevices := make([]volumeprobe.ObservedBlockDevice, 0, len(discovery.candidates))
	for _, candidate := range discovery.candidates {
		observedDevices = append(observedDevices, volumeprobe.ObservedBlockDevice{
			Name: candidate.Name, Generation: candidate.Generation,
		})
	}
	if len(observedDevices) != 2 || observedDevices[0].Name != "sdb" || observedDevices[1].Name != "sdc" {
		return errors.New("complete QEMU discovery did not classify exactly the two unmounted leaf data disks as candidates")
	}
	deviceIDs := make(map[string]bool)
	deviceGenerations := make(map[string]volumeprobe.BlockDeviceGeneration)
	for _, device := range observedDevices {
		deviceNumber := fmt.Sprintf("%d:%d", device.Generation.Major, device.Generation.Minor)
		deviceIDs[deviceNumber] = true
		deviceGenerations[device.Name] = device.Generation
	}
	if len(deviceIDs) != 2 || len(deviceGenerations) != 2 {
		return errors.New("fixture requires distinct virtual devices")
	}
	unmounted := func() error {
		currentInventory, err := collectStorage(os.DirFS("/sys"))
		if err != nil || !sameQEMUStorageInventory(initialInventory, currentInventory) {
			return errors.New("probe fixture storage topology changed")
		}
		mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
		if err != nil {
			return err
		}
		for _, device := range []string{"sdb", "sdc"} {
			var disk *blockObservation
			for index := range currentInventory.Observations {
				observation := &currentInventory.Observations[index]
				if observation.Name == device {
					disk = observation
					break
				}
			}
			if disk == nil {
				return errors.New("probe fixture disk disappeared from sysfs")
			}
			mounted, err := observedWholeDiskHasVisibleDependentMount(*disk, currentInventory.Observations, mounts.Mounts)
			if err != nil || mounted {
				return errors.New("probe fixture disk has a visible mount through an observed dependent node")
			}
		}
		return nil
	}
	if err := unmounted(); err != nil {
		return err
	}
	fdEntriesBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	incompleteSources, err := volumeprobe.OpenObservedBlockSources([]volumeprobe.ObservedBlockDevice{
		observedDevices[0],
		{Name: "phantowd-missing-device", Generation: volumeprobe.BlockDeviceGeneration{Major: 255, Minor: 255, DiskSequence: ^uint64(0)}},
	})
	fdEntriesAfter, fdErr := os.ReadDir("/proc/self/fd")
	if !errors.Is(err, volumeprobe.ErrUnsafe) || incompleteSources != nil || fdErr != nil || len(fdEntriesBefore) != len(fdEntriesAfter) {
		return errors.New("incomplete QEMU source set leaked a descriptor or returned partial sources")
	}
	if err := volumeprobe.VerifyQEMUSymlinkRefusal(observedDevices[0]); err != nil {
		return errors.New("QEMU source opener followed a /dev symlink")
	}
	blockSources := discovery.sources
	var sources []*os.File
	for _, blockSource := range blockSources {
		sources = append(sources, blockSource.File)
	}
	finalInventory, err := collectStorage(os.DirFS("/sys"))
	if err != nil || !sameQEMUStorageInventory(initialInventory, finalInventory) {
		return errors.New("QEMU sysfs inventory changed while opening the fixture source set")
	}
	inventoryGenerations := []volumeprobe.BlockDeviceGeneration{
		deviceGenerations["sdb"], deviceGenerations["sdc"],
	}
	orderedSources, err := volumeprobe.OrderCompleteBlockSources(inventoryGenerations, []volumeprobe.BlockDeviceSource{
		blockSources[1], blockSources[0], // Deliberately shuffled: output must follow the observed inventory.
	})
	if err != nil || len(orderedSources) != 2 ||
		orderedSources[0].File != blockSources[0].File || orderedSources[1].File != blockSources[1].File {
		return errors.New("complete QEMU source set did not bind to sysfs inventory order")
	}
	snapshot, err := volumeprobe.ObserveBlockSet(context.Background(), []volumeprobe.BlockDeviceSource{orderedSources[0], orderedSources[1], orderedSources[0]})
	if err != nil {
		return err
	}
	if len(snapshot.Results()) != 3 {
		return errors.New("incomplete virtual probe snapshot")
	}
	for _, result := range snapshot.Results() {
		if result.Status != "ext-metadata" || result.SourceKind != "block-device" || result.Filesystem != "ext2" || result.FilesystemUUID != qemuNFSVolumeUUID {
			return errors.New("unmounted virtual metadata did not match")
		}
	}
	match, err := snapshot.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "conflicting-objects" || len(match.SourceIndices) != 3 {
		return errors.New("unmounted clone conflict missed")
	}
	alias, err := volumeprobe.ObserveBlockSet(context.Background(), []volumeprobe.BlockDeviceSource{orderedSources[0], orderedSources[0]})
	if err != nil {
		return err
	}
	match, err = alias.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "one-object" || len(match.SourceIndices) != 2 {
		return errors.New("same block object mistaken for clone")
	}
	staleGeneration := orderedSources[0]
	staleGeneration.Generation.DiskSequence++
	stale, err := volumeprobe.ObserveBlockSet(context.Background(), []volumeprobe.BlockDeviceSource{staleGeneration})
	if !errors.Is(err, volumeprobe.ErrUnsafe) || len(stale.Results()) != 0 {
		return errors.New("stale block generation was accepted")
	}
	match, err = snapshot.MatchUUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil || match.State != "not-observed" || len(match.SourceIndices) != 0 {
		return errors.New("unobserved UUID gained a match")
	}
	blank, err := os.CreateTemp("/run", "phantowd-probe-blank-")
	if err != nil {
		return err
	}
	name := blank.Name()
	defer os.Remove(name)
	if err := blank.Truncate(4096); err != nil {
		blank.Close()
		return err
	}
	blank.Close()
	blank, err = os.Open(name)
	if err != nil {
		return err
	}
	result, err := runProbeFixture(blank)
	blank.Close()
	if err != nil || result.Status != "unidentified" || result.SourceKind != "regular-image" || result.Filesystem != "" || result.FilesystemUUID != "" {
		return fmt.Errorf("unidentified regular-image fixture failed: %v", err)
	}
	if err := unmounted(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_VOLUME_PROBE_READY backend=libblkid unmounted_devices=2 readonly_descriptors=true expected_uuid=true unidentified_not_empty=true scope=qemu-fixture-only")
	fmt.Println("PHANTOWD_VOLUME_SET_READY cloned_uuid=true aliases_deduplicated=true generation_bound=true stale_generation_refused=true unobserved_not_absent=true shuffled_complete_set=true trusted_complete_discovery=true mount_swap_rechecked=true sysfs_rechecked=true observed_opener=true readonly_sources=true all_or_error=true symlink_refused=true scope=qemu-fixture-only")
	if err := probeQEMUCollisions(sources[0]); err != nil {
		return err
	}
	if err := unmounted(); err != nil {
		return err
	}
	return nil
}

func sameQEMUStorageInventory(a, b storageSnapshot) bool {
	return sameStorageSnapshot(a, b)
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

type observedDeviceNumber struct {
	major uint32
	minor uint32
}

// observedBlockDeviceSet resolves explicitly selected non-partition block-node
// names against a complete in-memory sysfs collection and attaches their
// transient generations. The caller must separately establish that these
// nodes are eligible whole disks and unmounted. This function neither opens a
// device nor authorizes media use.
func observedBlockDeviceSet(snapshot storageSnapshot, selectedNames []string) ([]volumeprobe.ObservedBlockDevice, error) {
	if selectedNames == nil || len(selectedNames) > volumeprobe.MaxSources {
		return nil, errors.New("selected block-node set is unknown or exceeds its bound")
	}
	if snapshot.SchemaVersion != 2 || snapshot.Scope != "kernel-sysfs-only" ||
		!snapshot.InventoryReadOnly || snapshot.BlockDevicesOpened || snapshot.ContentRead ||
		snapshot.MutationsPerformed || snapshot.StableIdentityAvailable ||
		snapshot.Observations == nil || len(snapshot.Observations) > maxBlockEntries ||
		snapshot.DeviceCount != len(snapshot.Observations) {
		return nil, errors.New("storage snapshot is not a complete in-memory collection")
	}

	wholeByName := make(map[string]blockObservation, len(snapshot.Observations))
	deviceNumbers := make(map[observedDeviceNumber]bool, len(snapshot.Observations))
	diskSequences := make(map[uint64]bool, len(snapshot.Observations))
	partitions := make([]blockObservation, 0, len(snapshot.Observations))
	previousName := ""
	for _, observation := range snapshot.Observations {
		if !validBlockName(observation.Name) || previousName != "" && observation.Name <= previousName ||
			(observation.Major == 0 && observation.Minor == 0) {
			return nil, errors.New("storage snapshot contains invalid or unordered block metadata")
		}
		previousName = observation.Name
		deviceNumber := observedDeviceNumber{major: observation.Major, minor: observation.Minor}
		if deviceNumbers[deviceNumber] {
			return nil, errors.New("storage snapshot contains duplicate block device numbers")
		}
		deviceNumbers[deviceNumber] = true

		switch observation.Kind {
		case "block":
			if observation.PartitionNumber != 0 || observation.ParentName != "" ||
				observation.ParentMajor != nil || observation.ParentMinor != nil ||
				observation.parentDiskSeq != 0 || observation.diskSequence == 0 ||
				diskSequences[observation.diskSequence] {
				return nil, errors.New("storage snapshot contains invalid whole-disk generation metadata")
			}
			diskSequences[observation.diskSequence] = true
			wholeByName[observation.Name] = observation
		case "partition":
			if observation.PartitionNumber == 0 || observation.ParentName == "" ||
				observation.ParentMajor == nil || observation.ParentMinor == nil ||
				observation.parentDiskSeq == 0 || observation.diskSequence != 0 {
				return nil, errors.New("storage snapshot contains invalid partition-parent metadata")
			}
			partitions = append(partitions, observation)
		default:
			return nil, errors.New("storage snapshot contains an unknown block node kind")
		}
	}

	for _, partition := range partitions {
		parent, exists := wholeByName[partition.ParentName]
		if !exists || parent.Major != *partition.ParentMajor || parent.Minor != *partition.ParentMinor ||
			parent.diskSequence != partition.parentDiskSeq {
			return nil, errors.New("storage snapshot contains an incomplete partition-parent relation")
		}
	}

	devices := make([]volumeprobe.ObservedBlockDevice, 0, len(selectedNames))
	selected := make(map[string]bool, len(selectedNames))
	for _, name := range selectedNames {
		if !validBlockName(name) || selected[name] {
			return nil, errors.New("selected storage nodes are invalid or duplicated")
		}
		selected[name] = true
		observation, exists := wholeByName[name]
		if !exists {
			return nil, errors.New("selected storage node is absent or is a partition")
		}
		devices = append(devices, volumeprobe.ObservedBlockDevice{
			Name: name,
			Generation: volumeprobe.BlockDeviceGeneration{
				Major: observation.Major, Minor: observation.Minor, DiskSequence: observation.diskSequence,
			},
		})
	}
	return devices, nil
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

type observedDeviceNumber struct {
	major uint32
	minor uint32
}

// completeObservedBlockDeviceSet converts only a collector-produced, complete
// in-memory schema-v2 inventory to generation-bound whole-disk names. It never
// accepts a selected-name list, so an HTTP or downstream caller cannot turn a
// partial selection into a complete inventory. The result is not a stable
// identity, an eligibility decision, or mount authority.
func completeObservedBlockDeviceSet(snapshot storageSnapshot) ([]volumeprobe.ObservedBlockDevice, error) {
	if snapshot.SchemaVersion != 2 || snapshot.Scope != "kernel-sysfs-only" ||
		!snapshot.InventoryReadOnly || snapshot.BlockDevicesOpened || snapshot.ContentRead ||
		snapshot.MutationsPerformed || snapshot.StableIdentityAvailable ||
		!snapshot.collectionComplete ||
		snapshot.Observations == nil || len(snapshot.Observations) > maxBlockEntries ||
		snapshot.DeviceCount != len(snapshot.Observations) {
		return nil, errors.New("storage snapshot is not a complete in-memory collection")
	}

	byName := make(map[string]blockObservation, len(snapshot.Observations))
	deviceNumbers := make(map[observedDeviceNumber]bool, len(snapshot.Observations))
	diskSequences := make(map[uint64]bool, len(snapshot.Observations))
	targets := make(map[string]bool, len(snapshot.Observations))
	devices := make([]volumeprobe.ObservedBlockDevice, 0, len(snapshot.Observations))
	previousName := ""
	for _, observation := range snapshot.Observations {
		if !validBlockName(observation.Name) || previousName != "" && observation.Name <= previousName ||
			(observation.Major == 0 && observation.Minor == 0) ||
			!validObservedSysfsTarget(observation.sysfsTarget, observation.Name) || targets[observation.sysfsTarget] {
			return nil, errors.New("storage snapshot contains invalid or unordered block metadata")
		}
		previousName = observation.Name
		targets[observation.sysfsTarget] = true
		deviceNumber := observedDeviceNumber{major: observation.Major, minor: observation.Minor}
		if deviceNumbers[deviceNumber] {
			return nil, errors.New("storage snapshot contains duplicate block device numbers")
		}
		deviceNumbers[deviceNumber] = true
		byName[observation.Name] = observation

		switch observation.Kind {
		case "block":
			if observation.PartitionNumber != 0 || observation.ParentName != "" ||
				observation.ParentMajor != nil || observation.ParentMinor != nil ||
				observation.parentDiskSeq != 0 || observation.diskSequence == 0 ||
				diskSequences[observation.diskSequence] || !validIdentityStatus(observation.SerialStatus) ||
				!validIdentityStatus(observation.WWNStatus) {
				return nil, errors.New("storage snapshot contains invalid whole-disk generation metadata")
			}
			diskSequences[observation.diskSequence] = true
			devices = append(devices, volumeprobe.ObservedBlockDevice{
				Name: observation.Name,
				Generation: volumeprobe.BlockDeviceGeneration{
					Major: observation.Major, Minor: observation.Minor, DiskSequence: observation.diskSequence,
				},
			})
		case "partition":
			if observation.PartitionNumber == 0 || observation.ParentName == "" ||
				observation.ParentMajor == nil || observation.ParentMinor == nil ||
				observation.parentDiskSeq == 0 || observation.diskSequence != 0 {
				return nil, errors.New("storage snapshot contains invalid partition-parent metadata")
			}
		default:
			return nil, errors.New("storage snapshot contains an unknown block node kind")
		}
	}

	for _, observation := range snapshot.Observations {
		if observation.Kind == "partition" {
			parent, exists := byName[observation.ParentName]
			if !exists || parent.Kind != "block" || parent.Major != *observation.ParentMajor ||
				parent.Minor != *observation.ParentMinor || parent.diskSequence != observation.parentDiskSeq ||
				path.Dir(observation.sysfsTarget) != parent.sysfsTarget {
				return nil, errors.New("storage snapshot contains an incomplete partition-parent relation")
			}
		}
		seenLower := make(map[string]bool, len(observation.lowerBlocks))
		for _, reference := range observation.lowerBlocks {
			lower, exists := byName[reference.Name]
			if !exists || reference.Name == observation.Name || seenLower[reference.Name] ||
				!sameTopologyReference(lower, reference) {
				return nil, errors.New("storage snapshot contains an incomplete block dependency relation")
			}
			seenLower[reference.Name] = true
		}
	}
	if err := validateObservedStorageTopology(snapshot.Observations); err != nil {
		return nil, errors.New("storage snapshot contains invalid or cyclic block topology")
	}
	return devices, nil
}

func validObservedSysfsTarget(target, name string) bool {
	return target != "" && len(target) <= maxSysfsBlockLinkBytes && fs.ValidPath(target) &&
		!path.IsAbs(target) && strings.HasPrefix(target, "devices/") && path.Base(target) == name
}

func validIdentityStatus(status identityStatus) bool {
	switch status {
	case identityUnavailable, identityPresent, identityInvalid, identityAmbiguous, identityUnreadable:
		return true
	default:
		return false
	}
}

func validateObservedStorageTopology(inventory []blockObservation) error {
	byName := make(map[string]blockObservation, len(inventory))
	for _, observation := range inventory {
		byName[observation.Name] = observation
	}
	state := make(map[string]uint8, len(inventory))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return errors.New("cyclic block dependency")
		case 2:
			return nil
		}
		observation, exists := byName[name]
		if !exists {
			return errors.New("missing block dependency")
		}
		state[name] = 1
		if observation.Kind == "partition" {
			if err := visit(observation.ParentName); err != nil {
				return err
			}
		}
		for _, lower := range observation.lowerBlocks {
			if err := visit(lower.Name); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for _, observation := range inventory {
		if err := visit(observation.Name); err != nil {
			return err
		}
	}
	return nil
}

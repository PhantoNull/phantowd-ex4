// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"path"
	"sort"
	"strings"
)

const maxMountedFilesystemAnchors = 64

var errMountedStorageIdentityIncomplete = errors.New("mounted storage identity is incomplete")

type mountedFilesystemObservation struct {
	anchor         string
	filesystemUUID string
	mountID        uint64
	deviceMajor    uint32
	deviceMinor    uint32
}

type mountedFilesystemInventory struct {
	mounts           []mountedFilesystemObservation
	conflictingUUIDs []string
}

// mountedStorageIdentity is a private, point-in-time relationship. It is not
// a stable volume ID, global UUID uniqueness result, compatibility decision,
// or authority to mount, assemble, or modify storage.
type mountedStorageIdentity struct {
	anchor                 string
	filesystemUUID         string
	mountID                uint64
	sourceMajor            uint32
	sourceMinor            uint32
	sourceName             string
	filesystemUUIDConflict bool
	arrays                 []mdArrayStorageIdentity
	physicalDisks          []mountedPhysicalDiskIdentity
}

type mountedPhysicalDiskIdentity struct {
	diskName       string
	major          uint32
	minor          uint32
	diskSequence   uint64
	serialStatus   identityStatus
	wwnStatus      identityStatus
	serialEvidence [32]byte
	wwnEvidence    [32]byte
}

// correlateMountedStorageIdentity joins only already-mounted ext anchors to
// one complete in-memory sysfs inventory and MD bindings produced from that
// inventory. It reads no block data, changes no storage state, persists no
// identity, and returns no partial result when any relation is uncertain.
func correlateMountedStorageIdentity(storage storageSnapshot, arrays []mdArrayStorageIdentity, mounted mountedFilesystemInventory) ([]mountedStorageIdentity, error) {
	if _, err := completeObservedBlockDeviceSet(storage); err != nil {
		return nil, errMountedStorageIdentityIncomplete
	}
	conflicts, err := validateMountedIdentityInventory(mounted)
	if err != nil {
		return nil, errMountedStorageIdentityIncomplete
	}

	byName := make(map[string]blockObservation, len(storage.Observations))
	byDevice := make(map[observedDeviceNumber]blockObservation, len(storage.Observations))
	mdBlocks := make(map[string]blockObservation)
	for _, observation := range storage.Observations {
		byName[observation.Name] = observation
		byDevice[observedDeviceNumber{major: observation.Major, minor: observation.Minor}] = observation
		if observation.Kind == "block" && validMDName(observation.Name) {
			mdBlocks[observation.Name] = observation
		}
	}
	arrayBindings, err := validateMountedMDArrayBindings(byName, mdBlocks, arrays)
	if err != nil {
		return nil, errMountedStorageIdentityIncomplete
	}

	result := make([]mountedStorageIdentity, 0, len(mounted.mounts))
	for _, mount := range mounted.mounts {
		source, exists := byDevice[observedDeviceNumber{major: mount.deviceMajor, minor: mount.deviceMinor}]
		if !exists {
			return nil, errMountedStorageIdentityIncomplete
		}
		disks, err := physicalDisksBehind(source, byName, make(map[string]bool))
		if err != nil || len(disks) == 0 {
			return nil, errMountedStorageIdentityIncomplete
		}
		arrayNames, err := mdArraysBehind(source, byName)
		if err != nil {
			return nil, errMountedStorageIdentityIncomplete
		}
		mountedArrays := make([]mdArrayStorageIdentity, 0, len(arrayNames))
		for _, name := range arrayNames {
			binding, exists := arrayBindings[name]
			if !exists {
				return nil, errMountedStorageIdentityIncomplete
			}
			mountedArrays = append(mountedArrays, cloneMDArrayStorageIdentity(binding))
		}

		physicalDisks := make([]mountedPhysicalDiskIdentity, 0, len(disks))
		seenDevices := make(map[observedDeviceNumber]bool, len(disks))
		for _, disk := range disks {
			device := observedDeviceNumber{major: disk.Major, minor: disk.Minor}
			if seenDevices[device] {
				return nil, errMountedStorageIdentityIncomplete
			}
			seenDevices[device] = true
			physicalDisks = append(physicalDisks, mountedPhysicalDiskIdentity{
				diskName: disk.Name, major: disk.Major, minor: disk.Minor, diskSequence: disk.diskSequence,
				serialStatus: disk.SerialStatus, wwnStatus: disk.WWNStatus,
				serialEvidence: disk.serialEvidence, wwnEvidence: disk.wwnEvidence,
			})
		}
		sort.Slice(physicalDisks, func(i, j int) bool {
			if physicalDisks[i].major != physicalDisks[j].major {
				return physicalDisks[i].major < physicalDisks[j].major
			}
			return physicalDisks[i].minor < physicalDisks[j].minor
		})
		result = append(result, mountedStorageIdentity{
			anchor: mount.anchor, filesystemUUID: mount.filesystemUUID, mountID: mount.mountID,
			sourceMajor: mount.deviceMajor, sourceMinor: mount.deviceMinor, sourceName: source.Name,
			filesystemUUIDConflict: conflicts[mount.filesystemUUID], arrays: mountedArrays, physicalDisks: physicalDisks,
		})
	}
	return result, nil
}

func validateMountedIdentityInventory(mounted mountedFilesystemInventory) (map[string]bool, error) {
	if mounted.mounts == nil || len(mounted.mounts) == 0 || len(mounted.mounts) > maxMountedFilesystemAnchors || mounted.conflictingUUIDs == nil {
		return nil, errMountedStorageIdentityIncomplete
	}
	seenAnchors := make(map[string]bool, len(mounted.mounts))
	uuidDevices := make(map[string]map[observedDeviceNumber]bool)
	deviceUUIDs := make(map[observedDeviceNumber]string)
	for _, mount := range mounted.mounts {
		canonical, validUUID := canonicalMDArrayUUID(mount.filesystemUUID)
		if len(mount.anchor) == 0 || mount.anchor == "/" || len(mount.anchor) > 4096 || !path.IsAbs(mount.anchor) ||
			path.Clean(mount.anchor) != mount.anchor || strings.ContainsRune(mount.anchor, 0) ||
			seenAnchors[mount.anchor] || !validUUID || canonical != mount.filesystemUUID ||
			mount.mountID == 0 || mount.deviceMajor == 0 {
			return nil, errMountedStorageIdentityIncomplete
		}
		seenAnchors[mount.anchor] = true
		device := observedDeviceNumber{major: mount.deviceMajor, minor: mount.deviceMinor}
		if previousUUID, exists := deviceUUIDs[device]; exists && previousUUID != mount.filesystemUUID {
			return nil, errMountedStorageIdentityIncomplete
		}
		deviceUUIDs[device] = mount.filesystemUUID
		if uuidDevices[mount.filesystemUUID] == nil {
			uuidDevices[mount.filesystemUUID] = make(map[observedDeviceNumber]bool)
		}
		uuidDevices[mount.filesystemUUID][device] = true
	}

	conflicts := make([]string, 0)
	conflictingUUIDs := make(map[string]bool)
	for uuid, devices := range uuidDevices {
		if len(devices) > 1 {
			conflicts = append(conflicts, uuid)
			conflictingUUIDs[uuid] = true
		}
	}
	sort.Strings(conflicts)
	if len(conflicts) != len(mounted.conflictingUUIDs) {
		return nil, errMountedStorageIdentityIncomplete
	}
	for index := range conflicts {
		if conflicts[index] != mounted.conflictingUUIDs[index] {
			return nil, errMountedStorageIdentityIncomplete
		}
	}
	return conflictingUUIDs, nil
}

func validateMountedMDArrayBindings(byName map[string]blockObservation, mdBlocks map[string]blockObservation, arrays []mdArrayStorageIdentity) (map[string]mdArrayStorageIdentity, error) {
	if arrays == nil || len(arrays) > maxMDArrayEntries || len(arrays) != len(mdBlocks) {
		return nil, errMountedStorageIdentityIncomplete
	}
	result := make(map[string]mdArrayStorageIdentity, len(arrays))
	seenUUIDs := make(map[string]bool, len(arrays))
	for _, binding := range arrays {
		block, exists := mdBlocks[binding.arrayName]
		if !exists || block.Kind != "block" || result[binding.arrayName].arrayName != "" ||
			block.Major != binding.arrayMajor || block.Minor != binding.arrayMinor ||
			block.diskSequence == 0 || block.diskSequence != binding.arrayDiskSeq ||
			!canonicalPrivateMDUUID(binding.arrayUUID) || seenUUIDs[binding.arrayUUID] ||
			!validMDLevel(binding.level) || len(block.lowerBlocks) == 0 || len(binding.memberDisks) == 0 {
			return nil, errMountedStorageIdentityIncomplete
		}
		expectedMembers := make([]mdMemberDiskIdentity, 0, len(binding.memberDisks))
		seenMemberDevices := make(map[observedDeviceNumber]bool, len(binding.memberDisks))
		for _, reference := range block.lowerBlocks {
			member, exists := byName[reference.Name]
			if !exists || !sameTopologyReference(member, reference) {
				return nil, errMountedStorageIdentityIncomplete
			}
			disks, err := physicalDisksBehind(member, byName, make(map[string]bool))
			if err != nil || len(disks) == 0 {
				return nil, errMountedStorageIdentityIncomplete
			}
			for _, disk := range disks {
				device := observedDeviceNumber{major: disk.Major, minor: disk.Minor}
				if seenMemberDevices[device] || !diskIdentityEvidenceUnique(disk) {
					return nil, errMountedStorageIdentityIncomplete
				}
				seenMemberDevices[device] = true
				expectedMembers = append(expectedMembers, mdMemberDiskIdentity{
					memberName: member.Name, diskName: disk.Name, major: disk.Major, minor: disk.Minor,
					diskSequence: disk.diskSequence, serialStatus: disk.SerialStatus, wwnStatus: disk.WWNStatus,
					serialEvidence: disk.serialEvidence, wwnEvidence: disk.wwnEvidence,
				})
			}
		}
		sort.Slice(expectedMembers, func(i, j int) bool {
			if expectedMembers[i].major != expectedMembers[j].major {
				return expectedMembers[i].major < expectedMembers[j].major
			}
			return expectedMembers[i].minor < expectedMembers[j].minor
		})
		if len(expectedMembers) != len(binding.memberDisks) {
			return nil, errMountedStorageIdentityIncomplete
		}
		for index := range expectedMembers {
			if expectedMembers[index] != binding.memberDisks[index] {
				return nil, errMountedStorageIdentityIncomplete
			}
		}
		seenUUIDs[binding.arrayUUID] = true
		result[binding.arrayName] = binding
	}
	return result, nil
}

func mdArraysBehind(source blockObservation, byName map[string]blockObservation) ([]string, error) {
	visiting := make(map[string]bool)
	visited := make(map[string]bool)
	arrays := make(map[string]bool)
	var walk func(blockObservation) error
	walk = func(observation blockObservation) error {
		if visiting[observation.Name] {
			return errMountedStorageIdentityIncomplete
		}
		if visited[observation.Name] {
			return nil
		}
		visiting[observation.Name] = true
		defer delete(visiting, observation.Name)
		if observation.Kind == "partition" {
			parent, exists := byName[observation.ParentName]
			if !exists || parent.Kind != "block" || observation.ParentMajor == nil || observation.ParentMinor == nil ||
				parent.Major != *observation.ParentMajor || parent.Minor != *observation.ParentMinor ||
				parent.diskSequence != observation.parentDiskSeq || path.Dir(observation.sysfsTarget) != parent.sysfsTarget ||
				len(observation.lowerBlocks) != 0 {
				return errMountedStorageIdentityIncomplete
			}
			if err := walk(parent); err != nil {
				return err
			}
		} else if observation.Kind == "block" {
			if validMDName(observation.Name) {
				arrays[observation.Name] = true
			}
			for _, reference := range observation.lowerBlocks {
				lower, exists := byName[reference.Name]
				if !exists || !sameTopologyReference(lower, reference) {
					return errMountedStorageIdentityIncomplete
				}
				if err := walk(lower); err != nil {
					return err
				}
			}
		} else {
			return errMountedStorageIdentityIncomplete
		}
		visited[observation.Name] = true
		return nil
	}
	if err := walk(source); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(arrays))
	for name := range arrays {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func cloneMDArrayStorageIdentity(binding mdArrayStorageIdentity) mdArrayStorageIdentity {
	binding.memberDisks = append([]mdMemberDiskIdentity{}, binding.memberDisks...)
	return binding
}

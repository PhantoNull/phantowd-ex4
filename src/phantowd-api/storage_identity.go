// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"time"
)

var errMDIdentityInventoryIncomplete = errors.New("MD identity inventory is incomplete")

// mdArrayUUIDMatch is an internal comparison over one collector-produced
// sysfs inventory. It is not persistent identity, compatibility evidence or
// permission to open, assemble, mount or modify an array.
type mdArrayUUIDMatch struct {
	State        string
	ArrayIndices []int
}

// matchMDArrayUUID requires the complete sysfs array inventory, not a
// caller-selected subset. Two names for one major/minor object count as an
// alias; the same UUID on distinct kernel objects is a conflict.
func matchMDArrayUUID(snapshot mdArraySnapshot, uuid string) (mdArrayUUIDMatch, error) {
	canonical, valid := canonicalMDArrayUUID(uuid)
	if !valid || !snapshot.identityCollected || !snapshot.identityInventoryComplete ||
		snapshot.SchemaVersion != 1 || !snapshot.ReadOnly || snapshot.BlockDevicesOpened ||
		snapshot.DiskContentRead || snapshot.MutationsPerformed || snapshot.Arrays == nil ||
		len(snapshot.Arrays) > maxMDArrayEntries || snapshot.ArrayCount != len(snapshot.Arrays) {
		return mdArrayUUIDMatch{}, errMDIdentityInventoryIncomplete
	}

	match := mdArrayUUIDMatch{State: "not-observed", ArrayIndices: []int{}}
	objects := make(map[observedDeviceNumber]bool)
	seenNames := make(map[string]bool, len(snapshot.Arrays))
	uuidByObject := make(map[observedDeviceNumber]string, len(snapshot.Arrays))
	for index, array := range snapshot.Arrays {
		if !validMDName(array.Name) || seenNames[array.Name] || (array.major == 0 && array.minor == 0) ||
			!array.identityComplete || !canonicalPrivateMDUUID(array.arrayUUID) ||
			(array.uuidStatus != identityPresent && array.uuidStatus != identityAmbiguous) {
			return mdArrayUUIDMatch{}, errMDIdentityInventoryIncomplete
		}
		seenNames[array.Name] = true
		object := observedDeviceNumber{major: array.major, minor: array.minor}
		if previous, exists := uuidByObject[object]; exists && previous != array.arrayUUID {
			return mdArrayUUIDMatch{}, errMDIdentityInventoryIncomplete
		}
		uuidByObject[object] = array.arrayUUID
		if array.arrayUUID != canonical {
			continue
		}
		objects[object] = true
		match.ArrayIndices = append(match.ArrayIndices, index)
	}
	if len(objects) == 1 {
		match.State = "one-object"
	} else if len(objects) > 1 {
		match.State = "conflicting-objects"
	}
	return match, nil
}

func canonicalPrivateMDUUID(value string) bool {
	canonical, valid := canonicalMDArrayUUID(value)
	return valid && canonical == value
}

type mdMemberDiskIdentity struct {
	memberName     string
	diskName       string
	major          uint32
	minor          uint32
	diskSequence   uint64
	serialStatus   identityStatus
	wwnStatus      identityStatus
	serialEvidence [32]byte
	wwnEvidence    [32]byte
}

type mdArrayStorageIdentity struct {
	arrayName    string
	arrayUUID    string
	arrayMajor   uint32
	arrayMinor   uint32
	arrayDiskSeq uint64
	level        string
	memberDisks  []mdMemberDiskIdentity
}

// collectMDStorageIdentity samples complete storage and MD inventories on
// both sides of the correlation. Re-observation rejects observed topology,
// identifier, or generation changes; it remains a point-in-time check rather
// than an atomic kernel snapshot, storage lease, or mount authorization.
func collectMDStorageIdentity(sysfs, proc fs.FS) ([]mdArrayStorageIdentity, error) {
	_, identities, err := collectMDStorageIdentitySnapshot(sysfs, proc)
	return identities, err
}

// collectMDStorageIdentitySnapshot returns the same complete storage sample
// used for the MD bindings so a downstream in-memory join can avoid pairing a
// binding with an unrelated inventory generation.
func collectMDStorageIdentitySnapshot(sysfs, proc fs.FS) (storageSnapshot, []mdArrayStorageIdentity, error) {
	if sysfs == nil || proc == nil {
		return storageSnapshot{}, nil, errMDIdentityInventoryIncomplete
	}
	storageBefore, err := collectStorage(sysfs)
	if err != nil {
		return storageSnapshot{}, nil, errMDIdentityInventoryIncomplete
	}
	arraysBefore := collectMDArrayInventory(proc, sysfs, time.Now())
	arraysAfter := collectMDArrayInventory(proc, sysfs, time.Now())
	storageAfter, err := collectStorage(sysfs)
	if err != nil || !sameStorageSnapshot(storageBefore, storageAfter) || !sameMDIdentitySnapshot(arraysBefore, arraysAfter) {
		return storageSnapshot{}, nil, errMDIdentityInventoryIncomplete
	}
	identities, err := correlateMDStorageIdentity(storageBefore, arraysBefore)
	if err != nil {
		return storageSnapshot{}, nil, err
	}
	return storageBefore, identities, nil
}

func sameMDIdentitySnapshot(a, b mdArraySnapshot) bool {
	if !a.identityCollected || !b.identityCollected || !a.identityInventoryComplete || !b.identityInventoryComplete ||
		a.SchemaVersion != b.SchemaVersion || a.Status != b.Status || a.ReadOnly != b.ReadOnly ||
		a.BlockDevicesOpened != b.BlockDevicesOpened || a.DiskContentRead != b.DiskContentRead ||
		a.MutationsPerformed != b.MutationsPerformed || a.ArrayCount != b.ArrayCount || len(a.Arrays) != len(b.Arrays) {
		return false
	}
	for index := range a.Arrays {
		first, second := a.Arrays[index], b.Arrays[index]
		if first.Name != second.Name || first.major != second.major || first.minor != second.minor || first.Level != second.Level ||
			first.arrayUUID != second.arrayUUID || first.uuidStatus != second.uuidStatus ||
			!first.identityComplete || !second.identityComplete || !sameMDMemberNames(first.Members, second.Members) {
			return false
		}
	}
	return true
}

// correlateMDStorageIdentity binds stable MD UUIDs to the collector's
// complete, transient block topology and in-process disk identity evidence.
// It consumes only kernel observations; it opens no additional device and
// produces no ID suitable for persistence. Filesystem identity, GPT PARTUUID,
// WD layout compatibility and mount authority remain separate requirements.
func correlateMDStorageIdentity(storage storageSnapshot, arrays mdArraySnapshot) ([]mdArrayStorageIdentity, error) {
	if _, err := completeObservedBlockDeviceSet(storage); err != nil || !arrays.identityCollected ||
		!arrays.identityInventoryComplete || arrays.SchemaVersion != 1 || arrays.Status != arrayInventoryAvailable ||
		!arrays.ReadOnly || arrays.BlockDevicesOpened || arrays.DiskContentRead || arrays.MutationsPerformed ||
		arrays.Arrays == nil || len(arrays.Arrays) > maxMDArrayEntries || arrays.ArrayCount != len(arrays.Arrays) {
		return nil, errMDIdentityInventoryIncomplete
	}
	byName := make(map[string]blockObservation, len(storage.Observations))
	mdBlocks := make(map[string]blockObservation)
	for _, observation := range storage.Observations {
		byName[observation.Name] = observation
		if observation.Kind == "block" && validMDName(observation.Name) {
			mdBlocks[observation.Name] = observation
		}
	}
	if len(mdBlocks) != len(arrays.Arrays) {
		return nil, errMDIdentityInventoryIncomplete
	}

	result := make([]mdArrayStorageIdentity, 0, len(arrays.Arrays))
	for _, array := range arrays.Arrays {
		match, err := matchMDArrayUUID(arrays, array.arrayUUID)
		if err != nil || match.State != "one-object" || len(match.ArrayIndices) != 1 ||
			array.uuidStatus != identityPresent || !validMDLevel(array.Level) {
			return nil, errMDIdentityInventoryIncomplete
		}
		block, exists := mdBlocks[array.Name]
		if !exists || block.Major != array.major || block.Minor != array.minor || block.diskSequence == 0 ||
			len(block.lowerBlocks) == 0 || !sameMDMemberNames(array.Members, topologyMembers(block.lowerBlocks)) {
			return nil, errMDIdentityInventoryIncomplete
		}
		binding := mdArrayStorageIdentity{
			arrayName: array.Name, arrayUUID: array.arrayUUID,
			arrayMajor: array.major, arrayMinor: array.minor,
			arrayDiskSeq: block.diskSequence, level: array.Level,
			memberDisks: []mdMemberDiskIdentity{},
		}
		seenMemberNames := make(map[string]bool, len(array.Members))
		seenDiskNumbers := make(map[observedDeviceNumber]bool, len(array.Members))
		for _, member := range array.Members {
			if !validBlockName(member.Name) || seenMemberNames[member.Name] {
				return nil, errMDIdentityInventoryIncomplete
			}
			seenMemberNames[member.Name] = true
			memberObservation, exists := byName[member.Name]
			if !exists {
				return nil, errMDIdentityInventoryIncomplete
			}
			disks, err := physicalDisksBehind(memberObservation, byName, make(map[string]bool))
			if err != nil || len(disks) == 0 {
				return nil, errMDIdentityInventoryIncomplete
			}
			for _, disk := range disks {
				device := observedDeviceNumber{major: disk.Major, minor: disk.Minor}
				if seenDiskNumbers[device] || !diskIdentityEvidenceUnique(disk) {
					return nil, errMDIdentityInventoryIncomplete
				}
				seenDiskNumbers[device] = true
				binding.memberDisks = append(binding.memberDisks, mdMemberDiskIdentity{
					memberName: member.Name, diskName: disk.Name,
					major: disk.Major, minor: disk.Minor, diskSequence: disk.diskSequence,
					serialStatus: disk.SerialStatus, wwnStatus: disk.WWNStatus,
					serialEvidence: disk.serialEvidence, wwnEvidence: disk.wwnEvidence,
				})
			}
		}
		sort.Slice(binding.memberDisks, func(i, j int) bool {
			if binding.memberDisks[i].major != binding.memberDisks[j].major {
				return binding.memberDisks[i].major < binding.memberDisks[j].major
			}
			return binding.memberDisks[i].minor < binding.memberDisks[j].minor
		})
		result = append(result, binding)
	}
	return result, nil
}

func topologyMembers(references []blockTopologyRef) []mdMemberObservation {
	members := make([]mdMemberObservation, len(references))
	for index, reference := range references {
		members[index] = mdMemberObservation{Name: reference.Name}
	}
	return members
}

func physicalDisksBehind(observation blockObservation, byName map[string]blockObservation, visiting map[string]bool) ([]blockObservation, error) {
	if visiting[observation.Name] {
		return nil, errMDIdentityInventoryIncomplete
	}
	visiting[observation.Name] = true
	defer delete(visiting, observation.Name)
	if observation.Kind == "partition" {
		parent, exists := byName[observation.ParentName]
		if !exists || parent.Kind != "block" || observation.ParentMajor == nil || observation.ParentMinor == nil ||
			parent.Major != *observation.ParentMajor || parent.Minor != *observation.ParentMinor ||
			parent.diskSequence != observation.parentDiskSeq || path.Dir(observation.sysfsTarget) != parent.sysfsTarget {
			return nil, errMDIdentityInventoryIncomplete
		}
		return physicalDisksBehind(parent, byName, visiting)
	}
	if observation.Kind != "block" {
		return nil, errMDIdentityInventoryIncomplete
	}
	if len(observation.lowerBlocks) == 0 {
		if isVirtualBlockTarget(observation.sysfsTarget) || observation.diskSequence == 0 {
			return nil, errMDIdentityInventoryIncomplete
		}
		return []blockObservation{observation}, nil
	}
	disks := make([]blockObservation, 0, len(observation.lowerBlocks))
	seen := make(map[string]bool, len(observation.lowerBlocks))
	for _, reference := range observation.lowerBlocks {
		lower, exists := byName[reference.Name]
		if !exists || !sameTopologyReference(lower, reference) || seen[reference.Name] {
			return nil, errMDIdentityInventoryIncomplete
		}
		seen[reference.Name] = true
		resolved, err := physicalDisksBehind(lower, byName, visiting)
		if err != nil {
			return nil, err
		}
		disks = append(disks, resolved...)
	}
	return disks, nil
}

func diskIdentityEvidenceUnique(disk blockObservation) bool {
	if disk.SerialStatus == identityAmbiguous || disk.WWNStatus == identityAmbiguous {
		return false
	}
	serial := disk.SerialStatus == identityPresent && disk.serialEvidence != ([32]byte{})
	wwn := disk.WWNStatus == identityPresent && disk.wwnEvidence != ([32]byte{})
	return serial || wwn
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"sort"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

var errMountedVolumeReviewIncomplete = errors.New("scoped mounted-volume review is incomplete")

type desiredMountedVolumeObservation struct {
	volumeID                     shareconfig.VolumeID
	status                       string
	objectCount, aliasCount      int
	scopedDiskEvidenceUnresolved bool
}

// Observed means only found in one point-in-time mount-namespace census.
// No field carries a selected path, qualifier, retained handle or lease.
type desiredMountedVolumeReview struct {
	policyRevision                    uint64
	coverage                          mountedExtCensusCoverage
	objectCount, unclaimedObjectCount int
	volumes                           []desiredMountedVolumeObservation
}

func (desiredMountedVolumeReview) MarshalJSON() ([]byte, error) {
	return nil, errMountedVolumeReviewIncomplete
}

func (*desiredMountedVolumeReview) UnmarshalJSON([]byte) error {
	return errMountedVolumeReviewIncomplete
}

// reviewDesiredMountedVolumes performs no I/O. Expected UUIDs/VolumeIDs are
// validated desired-policy claims, not trusted persistent volume registration.
// Validate the full observation before examining any desired subset.
func reviewDesiredMountedVolumes(policy shareconfig.Config, census trustedMountedExtCensus) (desiredMountedVolumeReview, error) {
	fail := func() (desiredMountedVolumeReview, error) {
		return desiredMountedVolumeReview{}, errMountedVolumeReviewIncomplete
	}
	if policy.Validate() != nil || validateMountedExtCensus(census) != nil {
		return fail()
	}
	type objectObservation struct {
		aliases    int
		unresolved bool
	}
	byUUID := make(map[string]map[observedDeviceNumber]objectObservation)
	for _, identity := range census.identities {
		objects := byUUID[identity.filesystemUUID]
		if objects == nil {
			objects = make(map[observedDeviceNumber]objectObservation)
			byUUID[identity.filesystemUUID] = objects
		}
		device := observedDeviceNumber{major: identity.sourceMajor, minor: identity.sourceMinor}
		object := objects[device]
		object.aliases++
		for _, disk := range identity.physicalDisks {
			// Reuse exactly the current complete-sysfs evidence rule. Even a
			// positive result is not durable/global identity or compatibility.
			if !diskIdentityEvidenceUnique(blockObservation{SerialStatus: disk.serialStatus, WWNStatus: disk.wwnStatus,
				serialEvidence: disk.serialEvidence, wwnEvidence: disk.wwnEvidence}) {
				object.unresolved = true
			}
		}
		objects[device] = object
	}
	result := desiredMountedVolumeReview{policyRevision: policy.Revision, coverage: census.coverage,
		volumes: make([]desiredMountedVolumeObservation, 0, len(policy.Volumes))}
	claimed := make(map[string]bool, len(policy.Volumes))
	for _, volume := range policy.Volumes {
		claimed[string(volume.FilesystemUUID)] = true
		objects := byUUID[string(volume.FilesystemUUID)]
		observed := desiredMountedVolumeObservation{volumeID: volume.ID, status: "not-observed-in-scope", objectCount: len(objects)}
		if len(objects) == 1 {
			observed.status = "observed-in-scope"
		} else if len(objects) > 1 {
			observed.status = "ambiguous-in-scope"
		}
		for _, object := range objects {
			observed.aliasCount += object.aliases
			observed.scopedDiskEvidenceUnresolved = observed.scopedDiskEvidenceUnresolved || object.unresolved
		}
		result.volumes = append(result.volumes, observed)
	}
	for uuid, objects := range byUUID {
		result.objectCount += len(objects)
		if !claimed[uuid] {
			result.unclaimedObjectCount += len(objects)
		}
	}
	sort.Slice(result.volumes, func(i, j int) bool { return result.volumes[i].volumeID < result.volumes[j].volumeID })
	return result, nil
}

// Rebuild relationships from complete stored observations rather than trusting
// a summary or the caller's identity slice. This does not refresh the kernel.
func validateMountedExtCensus(census trustedMountedExtCensus) error {
	anchors, coverage, err := planMountedExtCensus(census.storage, census.mounts)
	if err != nil || coverage != census.coverage || census.identities == nil || len(census.identities) != len(anchors) ||
		!mountedCensusRootsMatch(census.roots, anchors, census.mounts) {
		return errMountedVolumeReviewIncomplete
	}
	byName := make(map[string]blockObservation, len(census.storage.Observations))
	mdBlocks := make(map[string]blockObservation)
	for _, block := range census.storage.Observations {
		byName[block.Name] = block
		if block.Kind == "block" && validMDName(block.Name) {
			mdBlocks[block.Name] = block
		}
	}
	if _, err := validateMountedMDArrayBindings(byName, mdBlocks, census.arrays); err != nil {
		return errMountedVolumeReviewIncomplete
	}
	if len(anchors) == 0 {
		if len(census.roots.ConflictingUUIDs) != 0 {
			return errMountedVolumeReviewIncomplete
		}
		return nil
	}
	// The collector owns this independent root observation. Never recreate it
	// from the identity records being verified (a circular consistency check).
	rebuilt, err := correlateObservedMountedStorageIdentity(census.storage, census.arrays, census.roots)
	if err != nil {
		return errMountedVolumeReviewIncomplete
	}
	for i, actual := range census.identities {
		expected := rebuilt[i]
		if actual.anchor != expected.anchor || actual.filesystemUUID != expected.filesystemUUID || actual.mountID != expected.mountID ||
			actual.sourceMajor != expected.sourceMajor || actual.sourceMinor != expected.sourceMinor || actual.sourceName != expected.sourceName ||
			actual.filesystemUUIDConflict != expected.filesystemUUIDConflict || !sameMountedCensusArrays(actual.arrays, expected.arrays) ||
			actual.physicalDisks == nil || len(actual.physicalDisks) != len(expected.physicalDisks) {
			return errMountedVolumeReviewIncomplete
		}
		for j := range actual.physicalDisks {
			if actual.physicalDisks[j] != expected.physicalDisks[j] {
				return errMountedVolumeReviewIncomplete
			}
		}
	}
	return nil
}

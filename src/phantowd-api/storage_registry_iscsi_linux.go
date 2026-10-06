//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"sort"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
)

// This private point-in-time review carries no file path, UUID, device tuple,
// credential, session, retained descriptor or eligibility/activation bit.
type iscsiRegisteredBackingObservation struct {
	backingID                                iscsipolicy.BackingID
	observed                                 desiredMountedVolumeObservation
	kind                                     string
	physicalDiskCount, mdArrayCount          int
	smbPathOverlapCount, nfsPathOverlapCount int
}

type registeredISCSIVolumeReview struct {
	policyRevision, volumeRevision, registryRevision uint64
	coverage                                         mountedExtCensusCoverage
	objectCount, unclaimedObjectCount                int
	unreferencedRegisteredCount                      int
	backings                                         []iscsiRegisteredBackingObservation
}

func (registeredISCSIVolumeReview) MarshalJSON() ([]byte, error) {
	return nil, volumeregistry.ErrObservation
}

func (*registeredISCSIVolumeReview) UnmarshalJSON([]byte) error {
	return volumeregistry.ErrObservation
}

// Pure comparison. All desired inputs must be stable under the caller's
// ownership, just as in the SMB/NFS review. An observed volume is not an
// observed backing file, qualified filesystem, writable lease or global-use
// proof. Even RO shares can expose a live LUN; overlap is advisory only here.
func reviewRegisteredISCSIVolumes(p iscsipolicy.Policy, config fileservice.Config, snapshot volumeregistry.Snapshot, census trustedMountedExtCensus) (registeredISCSIVolumeReview, error) {
	if config.Validate() != nil || p.Validate(config.Shares) != nil {
		return registeredISCSIVolumeReview{}, volumeregistry.ErrObservation
	}
	policy, err := reviewRegisteredPolicyVolumes(config, snapshot, census)
	if err != nil {
		return registeredISCSIVolumeReview{}, volumeregistry.ErrObservation
	}
	backing, err := reviewRegisteredBacking(snapshot, census)
	if err != nil {
		return registeredISCSIVolumeReview{}, volumeregistry.ErrObservation
	}
	result := registeredISCSIVolumeReview{policyRevision: p.Revision, volumeRevision: config.Revision,
		registryRevision: policy.registryRevision, coverage: policy.coverage,
		objectCount: policy.objectCount, unclaimedObjectCount: policy.unclaimedObjectCount,
		backings: make([]iscsiRegisteredBackingObservation, 0, len(p.Backings))}
	referenced := make(map[string]bool, len(p.Backings))
	for _, desired := range p.Backings {
		observation := iscsiRegisteredBackingObservation{backingID: desired.ID}
		for _, volume := range policy.volumes {
			if volume.observed.volumeID == desired.VolumeID {
				observation.observed = volume.observed
				break
			}
		}
		if observation.observed.volumeID != desired.VolumeID {
			return registeredISCSIVolumeReview{}, volumeregistry.ErrObservation
		}
		for _, volume := range backing.volumes {
			if volume.observed.volumeID == desired.VolumeID {
				referenced[string(desired.VolumeID)] = true
				// A valid desired ID with the wrong expected UUID never consumes
				// the actual registry backing, even if that backing is observed.
				if observation.observed.status == "observed-in-scope" && observation.observed.objectCount == 1 {
					observation.kind = volume.kind
					observation.physicalDiskCount = volume.physicalDiskCount
					observation.mdArrayCount = volume.mdArrayCount
				}
				break
			}
		}
		for _, share := range config.Shares.Shares {
			if share.VolumeID == desired.VolumeID && iscsiConfiguredPathOverlap(share.RelativePath, desired.RelativePath) {
				observation.smbPathOverlapCount++
			}
		}
		for _, export := range config.NFS.Exports {
			if export.VolumeID == desired.VolumeID && iscsiConfiguredPathOverlap(export.RelativePath, desired.RelativePath) {
				observation.nfsPathOverlapCount++
			}
		}
		result.backings = append(result.backings, observation)
	}
	result.unreferencedRegisteredCount = len(backing.volumes) - len(referenced)
	sort.Slice(result.backings, func(i, j int) bool { return result.backings[i].backingID < result.backings[j].backingID })
	return result, nil
}

// Only already validated canonical, volume-relative paths enter this helper.
// Do not normalize, resolve symlinks/hardlinks or compare different VolumeIDs.
func iscsiConfiguredPathOverlap(a, b string) bool {
	return a == "." || b == "." || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

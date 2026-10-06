//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"sort"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Registry observations have separate provenance/revision from desired policy.
// They do not select a path, manufacture a persistent physical identity,
// provide a retained lease or construct a mount/service Owner.
type registeredMountedVolumeReview struct {
	registryRevision                  uint64
	coverage                          mountedExtCensusCoverage
	objectCount, unclaimedObjectCount int
	volumes                           []desiredMountedVolumeObservation
}

type policyRegisteredVolumeObservation struct {
	observed                      desiredMountedVolumeObservation
	smbShareCount, nfsExportCount int
}

// A comparison, not planner evidence: no selected path, retained handle,
// compatibility qualification or ready/activation bit can escape.
type registeredPolicyVolumeReview struct {
	policyRevision, registryRevision             uint64
	coverage                                     mountedExtCensusCoverage
	registeredCount, unreferencedRegisteredCount int
	objectCount, unclaimedObjectCount            int
	volumes                                      []policyRegisteredVolumeObservation
}

func (registeredPolicyVolumeReview) MarshalJSON() ([]byte, error) {
	return nil, volumeregistry.ErrObservation
}
func (*registeredPolicyVolumeReview) UnmarshalJSON([]byte) error {
	return volumeregistry.ErrObservation
}

func reviewRegisteredPolicyVolumes(config fileservice.Config, snapshot volumeregistry.Snapshot, census trustedMountedExtCensus) (registeredPolicyVolumeReview, error) {
	if config.Validate() != nil {
		return registeredPolicyVolumeReview{}, volumeregistry.ErrObservation
	}
	// Review the complete protected registry and census, not only requested IDs.
	registered, err := reviewRegisteredMountedVolumes(snapshot, census)
	if err != nil {
		return registeredPolicyVolumeReview{}, volumeregistry.ErrObservation
	}
	claims, err := snapshot.Claims()
	if err != nil {
		return registeredPolicyVolumeReview{}, volumeregistry.ErrObservation
	}
	byID := make(map[shareconfig.VolumeID]shareconfig.FilesystemUUID, len(claims.Volumes))
	for _, claim := range claims.Volumes {
		byID[claim.ID] = claim.FilesystemUUID
	}
	observations := make(map[shareconfig.VolumeID]desiredMountedVolumeObservation, len(registered.volumes))
	for _, observation := range registered.volumes {
		observations[observation.volumeID] = observation
	}
	shares, exports := make(map[shareconfig.VolumeID]int), make(map[shareconfig.VolumeID]int)
	for _, share := range config.Shares.Shares {
		shares[share.VolumeID]++
	}
	for _, export := range config.NFS.Exports {
		exports[export.VolumeID]++
	}
	result := registeredPolicyVolumeReview{policyRevision: config.Revision, registryRevision: registered.registryRevision,
		coverage: registered.coverage, registeredCount: len(claims.Volumes), objectCount: registered.objectCount,
		unclaimedObjectCount: registered.unclaimedObjectCount, volumes: make([]policyRegisteredVolumeObservation, 0, len(config.Shares.Volumes))}
	referenced := make(map[shareconfig.VolumeID]bool, len(config.Shares.Volumes))
	for _, volume := range config.Shares.Volumes {
		observation := desiredMountedVolumeObservation{volumeID: volume.ID, status: "not-registered"}
		expected, exists := byID[volume.ID]
		if exists {
			referenced[volume.ID] = true
			if expected != volume.FilesystemUUID {
				observation.status = "registry-policy-conflict"
			} else {
				observation = observations[volume.ID]
			}
		}
		result.volumes = append(result.volumes, policyRegisteredVolumeObservation{observed: observation,
			smbShareCount: shares[volume.ID], nfsExportCount: exports[volume.ID]})
	}
	result.unreferencedRegisteredCount = len(claims.Volumes) - len(referenced)
	sort.Slice(result.volumes, func(i, j int) bool { return result.volumes[i].observed.volumeID < result.volumes[j].observed.volumeID })
	return result, nil
}

func (registeredMountedVolumeReview) MarshalJSON() ([]byte, error) {
	return nil, volumeregistry.ErrObservation
}
func (*registeredMountedVolumeReview) UnmarshalJSON([]byte) error {
	return volumeregistry.ErrObservation
}

func reviewRegisteredMountedVolumes(snapshot volumeregistry.Snapshot, census trustedMountedExtCensus) (registeredMountedVolumeReview, error) {
	d, err := snapshot.Claims()
	if err != nil {
		return registeredMountedVolumeReview{}, volumeregistry.ErrObservation
	}
	// Reuse the full-census validator and scoped object/alias/clone semantics.
	// This conversion is private computation, never desired-policy publication.
	review, err := reviewDesiredMountedVolumes(shareconfig.Config{Format: shareconfig.Format,
		SchemaVersion: shareconfig.SchemaVersion, Revision: d.Revision, Volumes: d.Volumes,
		Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}, census)
	if err != nil {
		return registeredMountedVolumeReview{}, volumeregistry.ErrObservation
	}
	return registeredMountedVolumeReview{registryRevision: d.Revision, coverage: review.coverage,
		objectCount: review.objectCount, unclaimedObjectCount: review.unclaimedObjectCount, volumes: review.volumes}, nil
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
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

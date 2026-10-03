//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"

// A scoped topology observation, not a persistent backing selector. No raw
// UUID, device number/name, generation, path or retained handle escapes.
type registeredBackingObservation struct {
	observed                        desiredMountedVolumeObservation
	kind                            string
	physicalDiskCount, mdArrayCount int
}

type registeredBackingReview struct {
	registryRevision                  uint64
	coverage                          mountedExtCensusCoverage
	objectCount, unclaimedObjectCount int
	volumes                           []registeredBackingObservation
}

func (registeredBackingReview) MarshalJSON() ([]byte, error) {
	return nil, volumeregistry.ErrObservation
}

func (*registeredBackingReview) UnmarshalJSON([]byte) error {
	return volumeregistry.ErrObservation
}

// Whole-census validation precedes all selection. Missing or cloned UUIDs never
// choose a backing; unresolved physical evidence stays explicit. This performs
// no I/O and is not an eligibility, health or compatibility assessment.
func reviewRegisteredBacking(snapshot volumeregistry.Snapshot, census trustedMountedExtCensus) (registeredBackingReview, error) {
	registered, err := reviewRegisteredMountedVolumes(snapshot, census)
	if err != nil {
		return registeredBackingReview{}, volumeregistry.ErrObservation
	}
	claims, err := snapshot.Claims()
	if err != nil {
		return registeredBackingReview{}, volumeregistry.ErrObservation
	}
	byID := make(map[string]string, len(claims.Volumes))
	for _, claim := range claims.Volumes {
		byID[string(claim.ID)] = string(claim.FilesystemUUID)
	}
	byName := make(map[string]blockObservation, len(census.storage.Observations))
	for _, source := range census.storage.Observations {
		byName[source.Name] = source
	}
	byUUID := make(map[string]mountedStorageIdentity, len(census.identities))
	for _, identity := range census.identities {
		// Aliases are one kernel object; a cloned UUID is never consumed below.
		byUUID[identity.filesystemUUID] = identity
	}
	result := registeredBackingReview{registryRevision: registered.registryRevision,
		coverage: registered.coverage, objectCount: registered.objectCount,
		unclaimedObjectCount: registered.unclaimedObjectCount,
		volumes:              make([]registeredBackingObservation, 0, len(registered.volumes))}
	for _, observed := range registered.volumes {
		backing := registeredBackingObservation{observed: observed}
		if observed.status == "observed-in-scope" && observed.objectCount == 1 {
			identity, exists := byUUID[byID[string(observed.volumeID)]]
			if !exists {
				return registeredBackingReview{}, volumeregistry.ErrObservation
			}
			source, exists := byName[identity.sourceName]
			if !exists {
				return registeredBackingReview{}, volumeregistry.ErrObservation
			}
			backing.physicalDiskCount, backing.mdArrayCount = len(identity.physicalDisks), len(identity.arrays)
			backing.kind = "other-block-stack"
			if len(identity.arrays) != 0 {
				backing.kind = "md-backed-stack"
				if source.Kind == "block" && validMDName(source.Name) {
					backing.kind = "md-device"
				} else if source.Kind == "partition" && validMDName(source.ParentName) {
					backing.kind = "md-partition"
				}
			} else if source.Kind == "block" && len(source.lowerBlocks) == 0 && !isVirtualBlockTarget(source.sysfsTarget) {
				backing.kind = "physical-disk"
			} else if source.Kind == "partition" {
				parent := byName[source.ParentName]
				if len(parent.lowerBlocks) == 0 && !isVirtualBlockTarget(parent.sysfsTarget) {
					backing.kind = "physical-partition"
				}
			}
		}
		result.volumes = append(result.volumes, backing)
	}
	return result, nil
}

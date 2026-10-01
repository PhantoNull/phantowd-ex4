//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

// BuildFromOwners compiles one candidate while the fixed mounted-volume roster
// and the identity Owner are both locked and freshly observed. The lock order
// is always mounted-volume set first, identity Owner second. It returns only
// the non-serializable plan; no lock or activation authority escapes.
//
// The callbacks held by those Owners perform only evidence collection and
// deterministic in-memory planning. Native config validation, file writes,
// daemon control and any later transaction are deliberately outside this
// helper; an apply-capable owner must reacquire/revalidate evidence at its own
// transaction boundary.
func BuildFromOwners(
	ctx context.Context,
	config fileservice.Config,
	activeRevision uint64,
	identity *identityowner.Owner,
	storage *mountowner.MountedVolumeSet,
) (Plan, error) {
	if ctx == nil || identity == nil || storage == nil || ctx.Err() != nil {
		return Plan{}, ErrNotReady
	}

	var candidate Plan
	err := storage.WithEvidence(func(storageEvidence mountowner.MountedVolumeSetEvidence) error {
		if ctx.Err() != nil {
			return ErrNotReady
		}
		storageSnapshot, err := StorageFromMountedOwnerSet(storageEvidence)
		if err != nil {
			return err
		}
		return identity.WithFileServiceSnapshot(ctx, func(identityEvidence identityowner.FileServiceSnapshot) error {
			if ctx.Err() != nil {
				return ErrNotReady
			}
			identitySnapshot, err := identityFromOwnerEvidence(identityEvidence)
			if err != nil {
				return err
			}
			compiled, err := Build(config, activeRevision, identitySnapshot, storageSnapshot)
			if err != nil {
				return err
			}
			candidate = compiled
			return nil
		})
	})
	if err != nil {
		return Plan{}, err
	}
	return candidate, nil
}

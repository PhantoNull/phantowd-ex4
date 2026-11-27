// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

// MountShareRoots attaches only the directories requested by this candidate
// and pins their original descriptors under a complete mounted-roster lease.
// The caller keeps the original policy and identity leases through runtime
// verification and closes copied inputs before releasing these objects.
// Non-nil handles returned with an error retain uncertain teardown.
func (c SambaIsolatedCandidate) MountShareRoots(ctx context.Context, root string, storage *mountowner.MountedVolumeSet,
	serviceGroup uint32) (*mountowner.ServiceHandoff, *mountowner.ServiceSharePins, error) {
	return c.mountShareRoots(ctx, root, storage, serviceGroup, mountowner.NewServiceHandoff)
}

// MountPrivateShareRoots retains the original candidate below a root-only
// parent for a daemon that accepts inherited descriptors.
func (c SambaIsolatedCandidate) MountPrivateShareRoots(ctx context.Context, root string, storage *mountowner.MountedVolumeSet,
	serviceGroup uint32) (*mountowner.ServiceHandoff, *mountowner.ServiceSharePins, error) {
	return c.mountShareRoots(ctx, root, storage, serviceGroup, mountowner.NewDescriptorServiceHandoff)
}

func (c SambaIsolatedCandidate) mountShareRoots(ctx context.Context, root string, storage *mountowner.MountedVolumeSet,
	serviceGroup uint32, create func(string, *mountowner.MountedVolumeSet, []mountowner.ServiceShare, uint32) (*mountowner.ServiceHandoff, error)) (
	*mountowner.ServiceHandoff, *mountowner.ServiceSharePins, error) {
	if !c.valid || ctx == nil || storage == nil {
		return nil, nil, ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := c.checkShareStorage(storage); err != nil {
		return nil, nil, err
	}
	handoff, err := create(root, storage, c.shareRequests(), serviceGroup)
	if err != nil {
		return nil, nil, err
	}
	if _, err := handoff.Mount(ctx); err != nil {
		return closeFailedShareHandoff(handoff, nil, err)
	}
	pins, err := handoff.RetainShareRoots()
	if err != nil {
		return closeFailedShareHandoff(handoff, pins, err)
	}
	if err := c.VerifyShareRoots(storage, pins); err != nil {
		return closeFailedShareHandoff(handoff, pins, err)
	}
	if err := ctx.Err(); err != nil {
		return closeFailedShareHandoff(handoff, pins, err)
	}
	return handoff, pins, nil
}

func closeFailedShareHandoff(handoff *mountowner.ServiceHandoff, pins *mountowner.ServiceSharePins, cause error) (
	*mountowner.ServiceHandoff, *mountowner.ServiceSharePins, error) {
	if handoff.State() == mountowner.ServiceHandoffReview {
		return handoff, pins, cause
	}
	if pins != nil {
		if err := pins.Close(); err != nil {
			return handoff, pins, errors.Join(cause, err)
		}
	}
	if err := handoff.Close(); err != nil {
		return handoff, nil, errors.Join(cause, err)
	}
	return nil, nil, cause
}

// VerifyShareRoots checks the exact original roster, storage fingerprint and
// full declaration under the retained handoff. The service owner separately
// checks its policy generation, credential backend and process state.
func (c SambaIsolatedCandidate) VerifyShareRoots(storage *mountowner.MountedVolumeSet, pins *mountowner.ServiceSharePins) error {
	if !c.valid || storage == nil || pins == nil {
		return ErrNotReady
	}
	evidence, err := pins.VerifyRoster(storage, c.shareRequests())
	if err != nil {
		return err
	}
	return c.checkShareEvidence(evidence)
}

func (c SambaIsolatedCandidate) checkShareStorage(storage *mountowner.MountedVolumeSet) error {
	evidence, err := storage.Observe()
	if err != nil {
		return err
	}
	return c.checkShareEvidence(evidence)
}

func (c SambaIsolatedCandidate) checkShareEvidence(evidence mountowner.MountedVolumeSetEvidence) error {
	snapshot, err := StorageFromMountedOwnerSet(evidence)
	if err != nil {
		return err
	}
	if c.freshness.StorageGeneration != snapshot.Generation || c.freshness.StorageFingerprint != fingerprintStorageSnapshot(snapshot) {
		return ErrNotReady
	}
	return nil
}

func (c SambaIsolatedCandidate) shareRequests() []mountowner.ServiceShare {
	requests := make([]mountowner.ServiceShare, len(c.roots))
	for i, root := range c.roots {
		requests[i] = mountowner.ServiceShare{ID: root.ID, VolumeID: string(root.VolumeID),
			RelativePath: root.RelativePath, ReadOnly: root.ReadOnly}
	}
	return requests
}

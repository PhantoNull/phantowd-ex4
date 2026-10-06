//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"io/fs"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

// Only private scoped reviews escape. Neither original roots, raw identities,
// registry snapshots nor retained resources become caller-selected authority.
type registeredStorageReview struct {
	policy  registeredPolicyVolumeReview
	backing registeredBackingReview
	iscsi   registeredISCSIVolumeReview
}

func (registeredStorageReview) MarshalJSON() ([]byte, error) {
	return nil, volumeregistry.ErrObservation
}

func (*registeredStorageReview) UnmarshalJSON([]byte) error {
	return volumeregistry.ErrObservation
}

// Not connected to product startup or HTTP. The policy belongs to the caller,
// which must not mutate its slices concurrently. This sequential bracket is
// not an atomic/global snapshot, continued freshness, lease or activation gate.
func collectRegisteredStorageReview(ctx context.Context, config fileservice.Config, reader *volumeregistry.Reader, sysfs, proc fs.FS) (registeredStorageReview, error) {
	return collectRegisteredStorageReviewWith(ctx, config, reader, sysfs, proc, mountguard.ObserveMounted)
}

// The observer is an internal deterministic test seam, not a runtime backend.
func collectRegisteredStorageReviewWith(ctx context.Context, config fileservice.Config, reader *volumeregistry.Reader, sysfs, proc fs.FS, observe mountedExtRootObserver) (registeredStorageReview, error) {
	return collectRegisteredStorageReviewScope(ctx, config, nil, reader, sysfs, proc, observe)
}

func collectRegisteredISCSIStorageReview(ctx context.Context, config fileservice.Config, p iscsipolicy.Policy, reader *volumeregistry.Reader, sysfs, proc fs.FS) (registeredStorageReview, error) {
	return collectRegisteredStorageReviewScope(ctx, config, &p, reader, sysfs, proc, mountguard.ObserveMounted)
}

// One shared registry/census bracket for all reviews. No second independent
// census, and no result escapes before the final whole-scope/reader rechecks.
func collectRegisteredStorageReviewScope(ctx context.Context, config fileservice.Config, p *iscsipolicy.Policy, reader *volumeregistry.Reader, sysfs, proc fs.FS, observe mountedExtRootObserver) (registeredStorageReview, error) {
	fail := func() (registeredStorageReview, error) {
		return registeredStorageReview{}, volumeregistry.ErrObservation
	}
	if ctx == nil || ctx.Err() != nil || reader == nil || sysfs == nil || proc == nil || observe == nil || config.Validate() != nil || (p != nil && p.Validate(config.Shares) != nil) {
		return fail()
	}
	snapshot, err := reader.Read(ctx)
	if err != nil {
		return fail()
	}
	census, err := collectTrustedMountedExtCensusWith(ctx, sysfs, proc, observe)
	if err != nil {
		return fail()
	}
	policy, err := reviewRegisteredPolicyVolumes(config, snapshot, census)
	if err != nil {
		return fail()
	}
	backing, err := reviewRegisteredBacking(snapshot, census)
	if err != nil {
		return fail()
	}
	var iscsi registeredISCSIVolumeReview
	if p != nil {
		iscsi, err = reviewRegisteredISCSIVolumes(*p, config, snapshot, census)
		if err != nil {
			return fail()
		}
	}
	// Revalidate the entire scope, including unclaimed/excluded observations.
	// The last registry check covers mutation during either census collection.
	if recheckTrustedMountedExtCensusWith(ctx, census, sysfs, proc, observe) != nil ||
		reader.Recheck(ctx, snapshot) != nil || ctx.Err() != nil {
		return fail()
	}
	return registeredStorageReview{policy: policy, backing: backing, iscsi: iscsi}, nil
}

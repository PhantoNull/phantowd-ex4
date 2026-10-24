//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// BuildFromLeasedNASOwners derives DATA from the caller's original retained
// NAS policy/identity claims and mounted roster. No config/backend can be
// substituted by an operation. The policy mutex is not held during the existing
// storage -> identity locked derivation; the SAME policy lease is checked again
// afterwards. These bracketed samples are not an atomic three-owner admission.
//
// This helper acquires/releases no lease, opens/recovers no writer and activates
// nothing. The caller must retain and revalidate its authorities through its own
// transaction and verified teardown. ActiveRevision remains a trusted caller's
// assertion; neither it nor a returned Plan proves an applied service revision.
func BuildFromLeasedNASOwners(ctx context.Context, policy *naspolicystore.Lease, activeRevision uint64, identity *identityowner.FileServiceLease, storage *mountowner.MountedVolumeSet) (Plan, error) {
	if ctx == nil || policy == nil || identity == nil || storage == nil {
		return Plan{}, ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, errors.Join(ErrNotReady, err)
	}
	document, err := policy.Snapshot(ctx)
	if err != nil {
		return Plan{}, errors.Join(ErrNotReady, err)
	}
	if document.Validate() != nil {
		return Plan{}, ErrNotReady
	}
	plan, err := BuildFromRetainedOwners(ctx, document.FileServices, activeRevision, identity, storage)
	if err != nil {
		return Plan{}, errors.Join(ErrNotReady, err)
	}
	if err := policy.Verify(ctx); err != nil {
		return Plan{}, errors.Join(ErrNotReady, err)
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, errors.Join(ErrNotReady, err)
	}
	return plan, nil
}

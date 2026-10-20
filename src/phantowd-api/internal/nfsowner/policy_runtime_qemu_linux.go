//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// NewLeasedSourceRuntimeQEMU borrows ORIGINAL caller-held policy/identity
// claims and mounted roster, never a caller-provided config or backend.
// It remains a disposable-guest fixture, not product service admission.
func NewLeasedSourceRuntimeQEMU(ctx context.Context, roots *ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU, policy *naspolicystore.Lease, identity *identityowner.FileServiceLease, storage *mountowner.MountedVolumeSet, activeRevision uint64) (*SourceRuntimeQEMU, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if policy == nil || identity == nil || storage == nil {
		return nil, ErrInvalid
	}
	return newSourceRuntimeQEMU(ctx, roots, inputs, &sourcePolicyAuthority{
		policy: policy, identity: identity, storage: storage, activeRevision: activeRevision,
	})
}

// Borrowed original refs are immutable construction inputs, not per-operation
// injections. The caller must keep them through independently verified teardown.
// This wrapper never acquires/releases a policy or identity claim, mutates their
// owners or reopens state. Equality binds data to these observations; it does NOT
// establish atomic admission, applied-state history or sole NFSD-domain ownership.
type sourcePolicyAuthority struct {
	policy         *naspolicystore.Lease
	identity       *identityowner.FileServiceLease
	storage        *mountowner.MountedVolumeSet
	activeRevision uint64
}

func (a *sourcePolicyAuthority) verify(ctx context.Context, expected fileserviceplan.NFSv3Candidate) error {
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, a.policy, a.activeRevision, a.identity, a.storage)
	if err != nil {
		return err
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		return err
	}
	if !candidate.EquivalentTo(expected) {
		return runtimebundle.ErrMismatch
	}
	return nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
)

type sourcePolicyFixture struct {
	policyDirectory string   // Only the fresh private RAM role provisioned below; not product input.
	faultFile       *os.File // Original uncertain-close object, never retried or discarded.
	seedPolicy      *naspolicystore.Store
	seedLedger      *serviceaccountstore.Store
	policyOwner     *naspolicystore.Owner
	policy          *naspolicystore.Lease
	identity        *identityowner.Owner
	identityRef     *identityowner.FileServiceLease
	storage         *mountowner.MountedVolumeSet
}

// This is explicit NEW guest-only provisioning, never an Owner constructor's
// implicit initialization or recovery. Keep original partial refs on failure.
var sourcePolicyRetained *sourcePolicyFixture

func prepareSourcePolicy(ctx context.Context, config fileservice.Config, storage *mountowner.MountedVolumeSet) (*sourcePolicyFixture, error) {
	f := &sourcePolicyFixture{storage: storage}
	sourcePolicyRetained = f
	dir, err := os.MkdirTemp("/run", "nfs-policy-owner-")
	if err != nil {
		return nil, err
	}
	for _, role := range []string{"policy", "identity", "identity/registry", "identity/operations"} {
		if err := os.Mkdir(filepath.Join(dir, role), 0700); err != nil {
			return nil, err
		}
	}
	f.seedPolicy, err = naspolicystore.Open(filepath.Join(dir, "policy"))
	if err != nil {
		return nil, err
	}
	f.policyDirectory = filepath.Join(dir, "policy")
	document := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1, FileServices: config,
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
	if err := f.seedPolicy.Commit(0, document); err != nil {
		return nil, err
	}
	if err := f.seedPolicy.Close(); err != nil {
		return nil, err
	}
	f.seedPolicy = nil
	f.policyOwner, err = naspolicystore.OpenOwner(filepath.Join(dir, "policy"))
	if err != nil {
		return nil, err
	}
	f.policy, err = f.policyOwner.Acquire(ctx, 1)
	if err != nil {
		return nil, err
	}
	f.seedLedger, err = serviceaccountstore.Open(filepath.Join(dir, "identity/registry"))
	if err != nil {
		return nil, err
	}
	if err := f.seedLedger.Initialize(1800, 1810); err != nil {
		return nil, err
	}
	if err := f.seedLedger.Close(); err != nil {
		return nil, err
	}
	f.seedLedger = nil
	// No imported/offline identities exist in this guarded, diskless synthetic
	// inventory. The actual /etc Unix census is read independently by Owner.
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	f.identity, err = identityowner.Open(filepath.Join(dir, "identity"), inventory)
	if err != nil {
		return nil, err
	}
	snapshot, err := f.identity.FileServiceSnapshot(ctx)
	if err != nil || len(snapshot.Registry.Accounts) != 0 {
		return nil, errors.Join(errors.New("source identity census refused"), err)
	}
	f.identityRef, err = f.identity.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (f *sourcePolicyFixture) candidate(ctx context.Context, active uint64) (fileserviceplan.NFSv3Candidate, error) {
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, f.policy, active, f.identityRef, f.storage)
	if err != nil {
		return fileserviceplan.NFSv3Candidate{}, err
	}
	return plan.NFSv3TCPCandidate()
}

func (f *sourcePolicyFixture) verifyAdmission(ctx context.Context, roots *nfsowner.ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU) error {
	if !errors.Is(f.policyOwner.Close(), naspolicystore.ErrBusy) || !errors.Is(f.identity.Close(), identityowner.ErrBusy) {
		return errors.New("source claims failed to exclude parent closure")
	}
	unusedPolicy, err := f.policyOwner.Acquire(ctx, 1)
	if err != nil {
		return err
	}
	if err := unusedPolicy.Release(); err != nil {
		return err
	}
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(ctx, roots, inputs, unusedPolicy, f.identityRef, f.storage, 0); got != nil || !errors.Is(err, naspolicystore.ErrClosed) {
		return errors.New("released policy claim admitted source runtime")
	}
	snapshot, err := f.identity.FileServiceSnapshot(ctx)
	if err != nil {
		return err
	}
	unusedIdentity, err := f.identity.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		return err
	}
	if err := unusedIdentity.Release(); err != nil {
		return err
	}
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(ctx, roots, inputs, f.policy, unusedIdentity, f.storage, 0); got != nil || !errors.Is(err, identityowner.ErrUnavailable) {
		return errors.New("released identity claim admitted source runtime")
	}
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(ctx, roots, inputs, f.policy, f.identityRef, f.storage, 1); got != nil || !errors.Is(err, runtimebundle.ErrMismatch) {
		return errors.New("equal text with different freshness admitted source runtime")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(canceled, roots, inputs, f.policy, f.identityRef, f.storage, 0); got != nil || !errors.Is(err, context.Canceled) {
		return errors.New("canceled leased source construction admitted")
	}
	if f.policy.Verify(ctx) != nil || f.identityRef.Verify(ctx) != nil || roots.Check(ctx) != nil || inputs.Check(ctx) != nil {
		return errors.New("refused source construction consumed original authority")
	}
	return nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Retain original handles/errors on any failed fixture step. This role is NEW
// guest-only state; the adapter never provisions, opens or recovers a writer.
var qemuNASPlanRetained any
var qemuNASPlanCause error

func exerciseQEMUOwnerNASLeaseNFSPlan(ctx context.Context, config fileservice.Config, identity *identityowner.Owner, storage *mountowner.MountedVolumeSet, expected fileserviceplan.NFSv3Candidate) (result error) {
	phase := "prepare"
	defer func() {
		qemuNASPlanCause = result
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_LEASE_PLAN_FAILURE phase=%s\n", phase)
		}
	}()
	if ctx == nil || identity == nil || storage == nil || config.Revision != 2 {
		return errors.New("NAS plan fixture admission refused")
	}
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	refs := &struct {
		store    *naspolicystore.Store
		owner    *naspolicystore.Owner
		policy   *naspolicystore.Lease
		identity *identityowner.FileServiceLease
	}{}
	qemuNASPlanRetained = refs
	// Keep this role outside the existing Samba fixture's cleanup namespace.
	dir, err := os.MkdirTemp("/run", "phantowd-nas-plan-")
	if err != nil {
		return err
	}
	document := func(revision uint64) naspolicy.Config {
		c := config
		c.Revision, c.Shares.Revision, c.NFS.Revision, c.NFS.VolumeRevision = revision, revision, revision, revision
		return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: revision, FileServices: c,
			ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
				Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
	}
	refs.store, err = naspolicystore.Open(dir)
	if err != nil {
		return err
	}
	if err := refs.store.Commit(0, document(1)); err != nil {
		return err
	}
	if err := refs.store.Commit(1, document(2)); err != nil {
		return err
	}
	if err := refs.store.Close(); err != nil {
		return err
	}
	refs.store = nil
	refs.owner, err = naspolicystore.OpenOwner(dir)
	if err != nil {
		return err
	}
	refs.policy, err = refs.owner.Acquire(ctx, 2)
	if err != nil {
		return err
	}
	before, err := identity.FileServiceSnapshot(ctx)
	if err != nil {
		return err
	}
	refs.identity, err = identity.RetainFileServiceSnapshot(ctx, before.Fingerprint)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "nas-services.json")
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !errors.Is(refs.owner.Close(), naspolicystore.ErrBusy) || !errors.Is(refs.owner.Commit(ctx, 2, document(3)), naspolicystore.ErrBusy) {
		return errors.New("NAS policy lease failed to fence its parent")
	}
	phase = "initial-plan"
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage)
	if err != nil {
		return err
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil || !candidate.EquivalentTo(expected) {
		return errors.New("NAS-leased plan differs from original Owner/storage candidate")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(canceled, refs.policy, 0, refs.identity, storage); !errors.Is(err, fileserviceplan.ErrNotReady) || !errors.Is(err, context.Canceled) || failed.FreshAgainst(failed.Freshness()) {
		return errors.New("NAS plan canceled admission supplied evidence")
	}
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, &mountowner.MountedVolumeSet{}); !errors.Is(err, fileserviceplan.ErrNotReady) || failed.FreshAgainst(failed.Freshness()) {
		return errors.New("NAS plan accepted an unowned roster")
	}
	if refs.policy.Verify(ctx) != nil || refs.identity.Verify(ctx) != nil {
		return errors.New("NAS derivation consumed or poisoned caller leases")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		return errors.New("NAS planning modified desired bytes")
	}
	phase = "released-policy"
	if err := refs.policy.Release(); err != nil {
		return err
	}
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage); !errors.Is(err, naspolicystore.ErrClosed) || failed.FreshAgainst(failed.Freshness()) {
		return errors.New("released NAS lease supplied a plan")
	}
	if err := refs.owner.Commit(ctx, 2, document(3)); err != nil {
		return err
	}
	refs.policy, err = refs.owner.Acquire(ctx, 3)
	if err != nil {
		return err
	}
	phase = "new-policy-revision"
	newPlan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage)
	if err != nil {
		return err
	}
	newCandidate, err := newPlan.NFSv3TCPCandidate()
	_, oldTable, _, oldErr := candidate.Documents()
	_, newTable, _, newErr := newCandidate.Documents()
	if err != nil || oldErr != nil || newErr != nil || oldTable != newTable || newCandidate.EquivalentTo(candidate) || newPlan.Freshness().PolicyRevision != 3 {
		return errors.New("equal NFS text erased desired revision identity")
	}
	phase = "released-identity"
	if err := refs.identity.Release(); err != nil {
		return err
	}
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage); !errors.Is(err, fileserviceplan.ErrNotReady) || !errors.Is(err, identityowner.ErrUnavailable) || failed.FreshAgainst(failed.Freshness()) {
		return errors.New("released identity claim supplied a NAS plan")
	}
	refs.identity, err = identity.RetainFileServiceSnapshot(ctx, before.Fingerprint)
	if err != nil {
		return err
	}
	phase = "policy-replacement"
	original, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	saved := filepath.Join(dir, "original-policy")
	if err := os.Rename(path, saved); err != nil {
		return err
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		return err
	}
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage); !errors.Is(err, naspolicystore.ErrReview) || failed.FreshAgainst(failed.Freshness()) {
		return errors.New("byte-identical policy replacement supplied a NAS plan")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := os.Rename(saved, path); err != nil {
		return err
	}
	if failed, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, refs.policy, 0, refs.identity, storage); !errors.Is(err, naspolicystore.ErrReview) || failed.FreshAgainst(failed.Freshness()) || !errors.Is(refs.owner.Close(), naspolicystore.ErrBusy) || refs.identity.Verify(ctx) != nil {
		return errors.New("restored policy revived or released NAS planning authority")
	}
	phase = "release-unused-claims"
	// No consumer was started: these claims never authorized a running service.
	if err := refs.policy.Release(); err != nil {
		return err
	}
	if err := refs.owner.Close(); err != nil {
		return err
	}
	if err := refs.identity.Release(); err != nil {
		return err
	}
	final, err := identity.FileServiceSnapshot(ctx)
	if err != nil || final.Fingerprint != before.Fingerprint {
		return errors.New("NAS plan fixture modified identity evidence")
	}
	fmt.Println("PHANTOWD_NFS_LEASED_POLICY_PLAN_READY policy=original_nas_lease identity=original_retained_owner storage=mounted_roster policy_bracketed=true candidate=readonly parent_policy_close_blocked=true commit_blocked=true caller_leases_retained=true canceled_unchanged=true released_policy_refused=true released_identity_refused=true same_text_new_revision=true policy_drift_review=true restored_refused=true identity_unchanged=true policy_mutations=fixture_only activation=false endpoint=false scope=disposable-qemu-only")
	return nil
}

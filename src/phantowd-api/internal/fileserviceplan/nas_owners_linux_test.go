//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

func TestBuildFromLeasedNASOwnersRefusesMissingAndCanceledAuthority(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		for missing := range 3 {
			policy, identity, storage := &naspolicystore.Lease{}, &identityowner.FileServiceLease{}, &mountowner.MountedVolumeSet{}
			switch missing {
			case 0:
				policy = nil
			case 1:
				identity = nil
			case 2:
				storage = nil
			}
			plan, err := BuildFromLeasedNASOwners(ctx, policy, 0, identity, storage)
			if !errors.Is(err, ErrNotReady) || plan.FreshAgainst(plan.Freshness()) {
				t.Fatal("missing authority supplied a usable plan", err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan, err := BuildFromLeasedNASOwners(ctx, &naspolicystore.Lease{}, 0, &identityowner.FileServiceLease{}, &mountowner.MountedVolumeSet{})
	if !errors.Is(err, ErrNotReady) || !errors.Is(err, context.Canceled) || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("canceled admission lost its cause or supplied a plan", err)
	}
}

func TestBuildFromLeasedNASOwnersPreservesPolicyReviewWithoutPartialPlan(t *testing.T) {
	ctx := context.Background()
	config, _, _, _ := planInputs(t)
	config.Revision, config.Shares.Revision, config.NFS.Revision, config.NFS.VolumeRevision = 1, 1, 1, 1
	document := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1, FileServices: config,
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := naspolicystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(0, document); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err := naspolicystore.OpenOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Release(); err != nil {
			t.Error(err)
		}
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	identity, storage := &identityowner.FileServiceLease{}, &mountowner.MountedVolumeSet{}
	if plan, err := BuildFromLeasedNASOwners(ctx, lease, 0, identity, storage); !errors.Is(err, ErrNotReady) || plan.FreshAgainst(plan.Freshness()) || lease.Verify(ctx) != nil {
		t.Fatal("invalid other authority poisoned or consumed healthy policy", err)
	}
	path := filepath.Join(dir, "nas-services.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid fixture policy"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildFromLeasedNASOwners(ctx, lease, 0, identity, storage)
	if !errors.Is(err, ErrNotReady) || !errors.Is(err, naspolicystore.ErrReview) || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("policy uncertainty lost its cause or supplied a partial plan", err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if plan, err := BuildFromLeasedNASOwners(ctx, lease, 0, identity, storage); !errors.Is(err, naspolicystore.ErrReview) || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("restored policy revived reviewed planning", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if plan, err := BuildFromLeasedNASOwners(ctx, lease, 0, identity, storage); !errors.Is(err, ErrNotReady) || !errors.Is(err, naspolicystore.ErrClosed) || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("released policy claim supplied a plan or lost its cause", err)
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

func lifecyclePolicyOwner(t *testing.T, consumer *writableOwner) (*naspolicystore.Owner, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "policy")
	source, err := createFixturePolicyOwner(directory, "synthetic/data")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := source.Acquire(context.Background(), 1)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	consumer.policy = lease
	// Native state-machine fixture only: independent test disposal, NOT consumer
	// stop verification or product recovery. Actual child/pin proof is in QEMU.
	t.Cleanup(func() {
		if consumer.policy != nil {
			consumer.policy.Release()
		}
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	return source, directory
}

func TestPolicyBoundLifecycleKeepsPrivateClaimUntilReferenceClosure(t *testing.T) {
	for _, kind := range []string{"normal", "drift", "uncertain", "file-close", "pin-close", "pre-start-drift", "post-start-drift"} {
		t.Run(kind, func(t *testing.T) {
			o, b := lifecycleOwner(t)
			source, dir := lifecyclePolicyOwner(t, o)
			ctx := context.Background()
			if !errors.Is(source.Commit(ctx, 1, fixtureBackingPolicy(2, "synthetic/data")), naspolicystore.ErrBusy) || !errors.Is(source.Close(), naspolicystore.ErrBusy) {
				t.Fatal("claim not fenced")
			}
			if kind == "pre-start-drift" {
				if err := mutateFixturePolicy(dir); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "post-start-drift" {
				b.onStart = func() {
					if err := mutateFixturePolicy(dir); err != nil {
						t.Fatal(err)
					}
				}
			}
			startErr := o.start(ctx)
			if kind == "pre-start-drift" || kind == "post-start-drift" {
				if !errors.Is(startErr, ErrReview) || !o.released || o.policy != nil {
					t.Fatal("launch bracket", startErr)
				}
				if kind == "pre-start-drift" && b.startCalls != 0 {
					t.Fatal("launch after prior policy loss")
				}
				if kind == "post-start-drift" && (b.stopCalls != 1 || !b.stopWithLiveReference) {
					t.Fatal("post-launch policy stop ordering")
				}
				return
			}
			if startErr != nil {
				t.Fatal(startErr)
			}
			switch kind {
			case "normal":
				if err := o.stop(ctx); err != nil {
					t.Fatal(err)
				}
				if !o.released || o.policy != nil || !b.stopWithLiveReference {
					t.Fatal("policy released early")
				}
				if err := source.Commit(ctx, 1, fixtureBackingPolicy(2, "synthetic/data")); err != nil {
					t.Fatal(err)
				}
				return
			case "drift", "uncertain":
				if kind == "uncertain" {
					b.stopError = ErrReview
				}
				if err := mutateFixturePolicy(dir); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(o.observe(ctx), ErrReview) {
					t.Fatal("policy drift not reviewed")
				}
			case "file-close":
				if err := o.file.Close(); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(o.stop(ctx), ErrReview) {
					t.Fatal("close uncertainty ignored")
				}
			case "pin-close":
				metadata, err := os.CreateTemp(t.TempDir(), "metadata-close-fault")
				if err != nil {
					t.Fatal(err)
				}
				o.pin.file = metadata
				if err := metadata.Close(); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(o.stop(ctx), ErrReview) {
					t.Fatal("pin close uncertainty ignored")
				}
			}
			if b.stopCalls != 1 {
				t.Fatal("stop not attempted exactly once")
			}
			for _, op := range []func() error{func() error { return o.start(ctx) }, func() error { return o.observe(ctx) }, func() error { return o.stop(ctx) }, o.close} {
				if !errors.Is(op(), ErrReview) {
					t.Fatal("review revived")
				}
			}
			if b.stopCalls != 1 {
				t.Fatal("stop retried")
			}
			if kind == "drift" {
				if !o.released || o.policy != nil {
					t.Fatal("confirmed stop retained unexpected claim")
				}
			} else {
				if o.released || o.policy == nil || !errors.Is(source.Close(), naspolicystore.ErrBusy) {
					t.Fatal("uncertainty abandoned policy")
				}
			}
		})
	}
}

func TestPolicyBackingSelectionAndFailedAdmissionConsumeNothing(t *testing.T) {
	for _, kind := range []string{"missing-id", "volume", "relative", "size", "unmounted", "descriptor", "stale", "nil-backend"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			source, err := createFixturePolicyOwner(filepath.Join(t.TempDir(), "desired"), "synthetic/data")
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			p := &Pin{mountRoot: &mountowner.VolumeRootPin{}, volumeID: "qemu-plan", directory: "synthetic", name: "data", fileIdentity: identity{size: 4096}}
			id, revision := "fixture-backing", uint64(1)
			backend := &lifecycleBackend{}
			switch kind {
			case "missing-id":
				id = "missing"
			case "volume":
				p.volumeID = "other"
			case "relative":
				p.name = "other"
			case "size":
				p.fileIdentity.size = 8192
			case "unmounted":
				p.mountRoot = nil
			case "stale":
				revision = 2
			case "nil-backend":
				backend = nil
			}
			f, err := os.CreateTemp(t.TempDir(), "unqualified")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			owner, err := newPolicyBoundWritableOwner(ctx, p, f, backend, source, revision, iscsipolicy.BackingID(id))
			if owner != nil || err == nil || p.consumer != nil {
				t.Fatal("unqualified descriptor admitted", err)
			}
			if _, err := f.Stat(); err != nil {
				t.Fatal("failed admission consumed caller file", err)
			}
			if err := source.Commit(ctx, 1, fixtureBackingPolicy(2, "synthetic/data")); err != nil {
				t.Fatal("failed admission stranded policy claim", err)
			}
		})
	}
}

func TestPolicySupervisionRetainsClaimAcrossCancellationAndDrift(t *testing.T) {
	for _, kind := range []string{"cancel", "cancel-uncertain", "drift", "drift-uncertain"} {
		t.Run(kind, func(t *testing.T) {
			owner, backend := lifecycleOwner(t)
			source, directory := lifecyclePolicyOwner(t, owner)
			ctx := context.Background()
			if err := owner.start(ctx); err != nil {
				t.Fatal(err)
			}
			cancel, done := startLifecycleSupervisor(t, owner)
			if !errors.Is(source.Commit(ctx, 1, fixtureBackingPolicy(2, "synthetic/data")), naspolicystore.ErrBusy) || !errors.Is(source.Close(), naspolicystore.ErrBusy) {
				t.Fatal("supervised consumer lost private policy claim")
			}
			owner.mu.Lock()
			if kind == "cancel-uncertain" || kind == "drift-uncertain" {
				backend.stopError = ErrUnavailable
			}
			owner.mu.Unlock()
			if kind == "drift" || kind == "drift-uncertain" {
				if err := mutateFixturePolicy(directory); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			err := awaitLifecycleSupervisor(t, done)
			if kind == "cancel" {
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReview) || owner.policy != nil || !owner.released {
					t.Fatal("healthy cancellation did not release after stop", err)
				}
				if err := source.Commit(ctx, 1, fixtureBackingPolicy(2, "synthetic/data")); err != nil {
					t.Fatal(err)
				}
			} else {
				if !errors.Is(err, ErrReview) || owner.phase != writableReview {
					t.Fatal("supervision fault not reviewed", err)
				}
				if kind != "drift" && (owner.policy == nil || owner.released || !errors.Is(source.Close(), naspolicystore.ErrBusy)) {
					t.Fatal("uncertain supervised consumer abandoned policy")
				}
				if !errors.Is(owner.supervise(ctx), ErrReview) || backend.stopCalls != 1 {
					t.Fatal("restored supervisor retried or revived")
				}
			}
			if backend.stopCalls != 1 || !backend.stopWithLiveReference {
				t.Fatal("policy release preceded supervised stop")
			}
		})
	}
}

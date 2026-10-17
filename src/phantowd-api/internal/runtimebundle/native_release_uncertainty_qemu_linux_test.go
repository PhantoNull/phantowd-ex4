//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Bundle admission is bypassed only to exercise teardown bookkeeping. These
// fixtures never start a child, qualify a bundle, mount a root or acquire devices.
func nativeReleaseFixture(t *testing.T) *NativeSambaRuntimeQEMU {
	t.Helper()
	executable, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	processes, err := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "unused", Process: processowner.Spec{
		Executable: "/fixed/unused", Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}, []*os.File{executable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = processes.Close() })
	owner := &Owner{gate: make(chan struct{}, 1), processes: processes}
	owner.self = owner // Controlled release bookkeeping, not bundle admission.
	return &NativeSambaRuntimeQEMU{owner: owner, gate: make(chan struct{}, 1)}
}

func TestNativeRuntimeClosePreservesTerminalReleaseFailure(t *testing.T) {
	for _, role := range []string{"owner", "authentication", "helper"} {
		t.Run(role, func(t *testing.T) {
			runtime := nativeReleaseFixture(t)
			helper := releaseFaultFile(t, role == "helper")
			runtime.helper = helper
			cause := os.ErrClosed
			var auth string
			if role == "owner" {
				root := releaseFaultFile(t, false)
				runtime.owner.retainedCode = &retainedCode{root: root, files: map[string]*os.File{"fault": releaseFaultFile(t, true)}}
				auth = filepath.Join(t.TempDir(), "auth")
				if err := os.WriteFile(auth, []byte("fixture-only"), 0600); err != nil {
					t.Fatal(err)
				}
				runtime.authPaths = []string{auth}
				t.Cleanup(func() { _ = os.Remove(auth) })
			}
			if role == "authentication" {
				cause = os.ErrNotExist
				auth = filepath.Join(t.TempDir(), "missing")
				runtime.authPaths = []string{auth}
			}
			first := runtime.Close(context.Background())
			if !errors.Is(first, ErrReviewRequired) || !errors.Is(first, cause) || !runtime.owner.review ||
				runtime.owner.snapshot.State != processowner.StateReviewRequired {
				t.Error("native wrapper lost terminal cleanup review", first, runtime.owner.review, runtime.owner.snapshot.State)
			}
			if role != "helper" {
				if _, err := helper.Stat(); err != nil {
					t.Error("failed earlier cleanup released the helper", err)
				}
			}
			if role == "owner" {
				if _, err := os.Stat(auth); err != nil {
					t.Error("failed Owner release continued authentication cleanup", err)
				}
			}
			// Repair is test-only: terminal uncertainty must not permit a
			// retry that closes/removes a replacement object.
			if role == "authentication" {
				if err := os.WriteFile(auth, []byte("replacement-fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if role == "helper" {
				helper = releaseFaultFile(t, false)
				runtime.helper = helper
			}
			if next := runtime.Close(context.Background()); !errors.Is(next, ErrReviewRequired) || !errors.Is(next, cause) {
				t.Error("repeated native Close forgot terminal uncertainty", next)
			}
			if retired, err := runtime.ObserveNativeRetirementQEMU(context.Background()); retired || err != nil {
				t.Error("uncertain release was published as verified retirement", retired, err)
			}
			if _, err := helper.Stat(); err != nil {
				t.Error("repeated native Close touched a retained or replacement helper", err)
			}
			if role == "authentication" {
				if _, err := os.Stat(auth); err != nil {
					t.Error("repeated native Close removed a replacement auth object", err)
				}
			}
		})
	}
}

func TestNativeRuntimeCloseNormalRepeatHasNoReview(t *testing.T) {
	runtime := nativeReleaseFixture(t)
	helper := releaseFaultFile(t, false)
	runtime.helper = helper
	if err := runtime.Close(context.Background()); err != nil || !runtime.closed || runtime.owner.review || runtime.helper != nil {
		t.Fatal("normal verified closure did not release all roles", err)
	}
	if _, err := helper.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("normal closure retained the helper", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal("normal repeated Close was not idempotent", err)
	}
	if retired, err := runtime.ObserveNativeRetirementQEMU(context.Background()); !retired || err != nil {
		t.Fatal("normal closure lost positive retirement observation", retired, err)
	}
}

func TestNativeRuntimeVerifiedReviewCloseDoesNotStrandHelper(t *testing.T) {
	r := nativeReleaseFixture(t)
	helper := releaseFaultFile(t, false)
	r.helper = helper
	r.owner.review = true // Lifecycle review, NOT an injected close failure.
	if err := r.Close(context.Background()); !errors.Is(err, ErrReviewRequired) || !r.closed || !r.owner.review {
		t.Fatal("verified retirement lost its review outcome", err)
	}
	if _, err := helper.Stat(); !errors.Is(err, os.ErrClosed) || r.helper != nil {
		t.Fatal("successful underlying release was mistaken for uncertain close", err)
	}
	if err := r.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("repeated close erased review", err)
	}
	if retired, err := r.ObserveNativeRetirementQEMU(context.Background()); !retired || err != nil {
		t.Fatal("review erased independently verified retirement", retired, err)
	}
}

func TestNativeRuntimeRetirementObservationCannotCloseOrBypassGate(t *testing.T) {
	r := nativeReleaseFixture(t)
	r.helper = releaseFaultFile(t, false)
	defer r.Close(context.Background())
	if retired, err := r.ObserveNativeRetirementQEMU(context.Background()); retired || err != nil {
		t.Fatal("observation manufactured retirement", retired, err)
	}
	if _, err := r.helper.Stat(); err != nil {
		t.Fatal("observation closed a retained helper", err)
	}
	r.gate <- struct{}{}
	if retired, err := r.ObserveNativeRetirementQEMU(context.Background()); retired || !errors.Is(err, processowner.ErrBusy) {
		t.Error("observation bypassed exclusive lifecycle gate", retired, err)
	}
	<-r.gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if retired, err := r.ObserveNativeRetirementQEMU(ctx); retired || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation was accepted", retired, err)
	}
	if retired, err := r.ObserveNativeRetirementQEMU(nil); retired || !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context observation was accepted", retired, err)
	}
}

func TestNativeRuntimeHeldCloseKeepsTerminalStopFailureAndOriginalInputs(t *testing.T) {
	// Teardown bookkeeping ONLY: real independent unused sets, no admitted
	// runtime, launched child, mounted grant or healthy authority is fabricated.
	r := nativeReleaseFixture(t)
	client := nativeReleaseFixture(t).owner.processes
	r.plannedClient = client
	r.helper = releaseFaultFile(t, false)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	first := r.Close(context.Background())
	if !errors.Is(first, ErrReviewRequired) || !errors.Is(first, processowner.ErrUnavailable) ||
		!r.owner.review || r.owner.snapshot.State != processowner.StateReviewRequired {
		t.Fatal("prematurely closed client did not publish terminal review:", first, r.owner.snapshot.State)
	}
	replacement := nativeReleaseFixture(t).owner.processes
	r.plannedClient = replacement // Test-only repair cannot revive the lifetime.
	for range 2 {
		if err := r.Close(context.Background()); !errors.Is(err, processowner.ErrUnavailable) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("terminal client failure was erased:", err)
		}
		if r.closed || r.plannedClient != replacement {
			t.Fatal("repeated failed Close discarded retained input ownership")
		}
		if _, err := r.helper.Stat(); err != nil {
			t.Fatal("repeated failed Close released original helper:", err)
		}
		if _, err := replacement.Observe(context.Background()); err != nil {
			t.Fatal("repeated failed Close touched replacement client set:", err)
		}
	}
}

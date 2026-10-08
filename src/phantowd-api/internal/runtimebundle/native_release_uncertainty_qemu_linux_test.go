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
	return &NativeSambaRuntimeQEMU{owner: &Owner{gate: make(chan struct{}, 1), processes: processes}, gate: make(chan struct{}, 1)}
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
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// These fault fixtures bypass input admission to exercise release bookkeeping
// only. They never launch a child, qualify a bundle or acquire mount authority.
func releaseFaultFile(t *testing.T, closed bool) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "release-fault-")
	if err != nil {
		t.Fatal(err)
	}
	if closed {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Cleanup(func() { _ = file.Close() })
	}
	return file
}

func TestRetainedReleaseKeepsCloseUncertaintyAndRemainingRoot(t *testing.T) {
	for _, role := range []string{"code", "configuration", "state"} {
		t.Run(role, func(t *testing.T) {
			root := releaseFaultFile(t, false)
			fault := releaseFaultFile(t, true)
			var release func() error
			var restore func(*os.File)
			if role == "state" {
				state := &retainedSambaState{root: root, files: map[string]*os.File{"fault": fault}}
				release = state.release
				restore = func(replacement *os.File) { state.files["fault"] = replacement }
			} else {
				code := &retainedCode{root: root, files: map[string]*os.File{"fault": fault}}
				restore = func(replacement *os.File) { code.files["fault"] = replacement }
				if role == "configuration" {
					release = (&retainedConfiguration{contents: code}).release
				} else {
					release = code.release
				}
			}
			first := release()
			if !errors.Is(first, os.ErrClosed) {
				t.Fatal("fault did not reach real file Close", first)
			}
			if _, err := root.Stat(); err != nil {
				t.Error("uncertain file close released the remaining root", err)
			}
			// Test-only restoration cannot turn an uncertain release into a
			// retry that closes a different object. No raw descriptor is reused.
			replacement := releaseFaultFile(t, false)
			restore(replacement)
			if next := release(); !errors.Is(next, os.ErrClosed) {
				t.Error("repeat release forgot uncertainty or retried cleanup", next)
			}
			if _, err := replacement.Stat(); err != nil {
				t.Error("repeat release touched a replacement descriptor", err)
			}
		})
	}
}

func TestOwnerCloseRetainsReviewAfterInputCloseFailure(t *testing.T) {
	for _, role := range []string{"code", "configuration", "service-configuration", "state"} {
		t.Run(role, func(t *testing.T) {
			original, err := os.Open("/usr/bin/sleep")
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			processes, err := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "unused", Process: processowner.Spec{
				Executable: "/fixed/unused", Ready: func(context.Context) (bool, error) { return true, nil },
				ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
			}}}, []*os.File{original})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = processes.Close() })
			root := releaseFaultFile(t, false)
			fault := releaseFaultFile(t, true)
			code := &retainedCode{root: root, files: map[string]*os.File{"fault": fault}}
			owner := &Owner{gate: make(chan struct{}, 1), processes: processes}
			switch role {
			case "code":
				owner.retainedCode = code
			case "configuration":
				owner.configuration = &retainedConfiguration{contents: code}
			case "service-configuration":
				owner.serviceConfiguration = &retainedConfiguration{contents: code}
			case "state":
				owner.sambaState = &retainedSambaState{root: root, files: map[string]*os.File{"fault": fault}}
			}
			var later *os.File
			if role != "state" {
				later = releaseFaultFile(t, false)
				owner.sambaState = &retainedSambaState{root: later}
			}
			first := owner.Close(context.Background())
			if !errors.Is(first, ErrReviewRequired) || !errors.Is(first, os.ErrClosed) ||
				!owner.review || owner.snapshot.State != processowner.StateReviewRequired {
				t.Error("input close failure was not sticky review", first, owner.review, owner.snapshot.State)
			}
			if _, err := root.Stat(); err != nil {
				t.Error("input close uncertainty released its remaining root", err)
			}
			if later != nil {
				if _, err := later.Stat(); err != nil {
					t.Error("uncertain input close continued releasing later roles", err)
				}
			}
			if next := owner.Close(context.Background()); !errors.Is(next, ErrReviewRequired) || !errors.Is(next, os.ErrClosed) {
				t.Error("repeat Owner.Close forgot its release failure", next)
			}
		})
	}
}

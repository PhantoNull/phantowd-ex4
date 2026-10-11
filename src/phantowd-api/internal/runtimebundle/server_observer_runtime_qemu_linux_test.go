//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerObserverRuntimeRefusesHostAndPreservesCallers(t *testing.T) {
	if serverObserverCodeGuardQEMU() == nil {
		t.Skip("host refusal; real lifetime is separately exercised in the guest")
	}
	plan, err := NewPlan([]File{exampleFile("usr/sbin/smbd")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	caller := os.NewFile(uintptr(fd), "host-runtime-refusal-root")
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		owned, err := newServerObserverRuntimeQEMU(context.Background(), plan, caller, caller, caller, [2]*os.File{caller, caller})
		if owned != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired observer runtime", err)
		}
		if err := plan.ProbeServerObserverRuntimeQEMU(context.Background(), caller); !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired daemon experiment", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if owned, err := newServerObserverRuntimeQEMU(ctx, plan, caller, caller, caller, [2]*os.File{caller, caller}); owned != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled constructor collected inputs", err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refusal leaked descriptors", len(before), len(after), err)
	}
	if _, err := caller.Stat(); err != nil {
		t.Fatal("refusal consumed caller", err)
	}
}

func TestServerObserverRuntimeCloseUncertaintyRetainsUnattemptedOriginalsWithoutRetry(t *testing.T) {
	first, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	r := &serverObserverRuntimeQEMU{gate: make(chan struct{}, 1), shares: [2]*os.File{first, second}}
	r.self = r
	if err := r.Close(); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("uncertain close was declared complete", err)
	}
	for range 3 {
		if err := r.Close(); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("close uncertainty was forgotten", err)
		}
		if _, err := second.Stat(); err != nil {
			t.Fatal("uncertain close consumed unattempted original", err)
		}
	}
	if _, err := r.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("partial reviewed runtime restarted", err)
	}
	if _, err := r.Stop(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("partial review was cleared", err)
	}
	copy := *r
	if err := copy.Close(); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied runtime acquired disposal authority", err)
	}
}

func TestServerObserverRuntimeReviewCloseNeverReleasesOriginalWorkerObject(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pin := os.NewFile(uintptr(fd), "retained-reviewed-object")
	defer pin.Close()
	closed, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	// Review must refuse before attempting ANY release, even if a later
	// original is already unavailable. No fabricated healthy daemon/state.
	r := &serverObserverRuntimeQEMU{gate: make(chan struct{}, 1), review: true,
		captureWorker: &serverCaptureWorkerQEMU{file: pin}, shares: [2]*os.File{closed, nil}}
	r.self = r
	for range 3 {
		if err := r.Close(); !errors.Is(err, ErrReviewRequired) || r.closed || r.releaseErr != nil {
			t.Fatal("review attempted disposal", err)
		}
		if _, err := pin.Stat(); err != nil {
			t.Fatal("review released original worker object", err)
		}
	}
}

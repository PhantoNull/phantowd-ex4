//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestSuperviseCancellationStopsBeforeExplicitRelease(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("could not start original fixture lifetime", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Hour) }()
	waitSupervisionExclusive(t, owner, done)
	cancel()
	if err := waitSupervisionResult(t, done); !errors.Is(err, context.Canceled) || errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("ordinary accepted cancellation did not settle cleanly", err)
	}
	state, err := owner.Observe()
	if err != nil || state != nfsowner.Stopped || backend.running || !backend.retained || backend.stops != 1 || backend.releases != 0 || backend.stopContextError != nil {
		t.Fatal("cancellation did not preserve stopped original authority", state, err)
	}
	if err := owner.Start(context.Background()); !errors.Is(err, nfsowner.ErrState) {
		t.Fatal("supervision cancellation made lifetime restartable", err)
	}
	if err := owner.Close(context.Background()); err != nil || backend.retained || backend.releases != 1 || backend.stops != 1 {
		t.Fatal("explicit final release failed or repeated stop", err)
	}
}

func TestSuperviseContinuesHealthyScansBeforeCanceledProbe(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("could not start fixture", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := 0
	backend.readyHook = func(context.Context) {
		scans++
		if scans == 3 {
			cancel()
		}
	}
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Second) }()
	select {
	case err := <-done:
		// Probe three proves two complete healthy checks reset the idle timer.
		// Cancellation inside that probe deliberately requires review rather
		// than making a racy assertion about reaching the idle-stop branch.
		if scans != 3 || !errors.Is(err, context.Canceled) || !errors.Is(err, nfsowner.ErrReviewRequired) || backend.running || !backend.retained || backend.stops != 1 || backend.releases != 0 {
			t.Fatal("healthy scans did not continue or canceled probe lost review", scans, err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("healthy supervision failed to make bounded progress")
	}
}

func TestSuperviseRetainsReviewOnPostReadinessDrift(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("could not start fixture", err)
	}
	bound := backend.bound
	backend.readyHook = func(context.Context) { backend.bound.StorageGeneration++ }
	if err := owner.Supervise(context.Background(), time.Second); !errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("post-readiness drift did not withdraw the service", err)
	}
	if backend.running || !backend.retained || backend.stops != 1 || backend.releases != 0 {
		t.Fatal("drift did not retain stopped original authority")
	}
	backend.bound = bound
	if err := owner.Supervise(context.Background(), time.Second); !errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("restored inputs revived supervised lifetime", err)
	}
	if owner.Close(context.Background()) == nil || backend.releases != 0 || backend.stops != 1 {
		t.Fatal("review released inputs or retried settlement")
	}
}

func TestSuperviseOwnsTheEntireLoopExclusively(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("could not start fixture", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Hour) }()
	waitSupervisionExclusive(t, owner, done)
	for _, call := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if err := call(context.Background()); !errors.Is(err, nfsowner.ErrBusy) {
			t.Fatal("another operation entered the supervised lifetime", err)
		}
	}
	cancel()
	if !errors.Is(waitSupervisionResult(t, done), context.Canceled) {
		t.Fatal("supervision did not settle after exclusion test")
	}
	if err := owner.Close(context.Background()); err != nil || backend.retained {
		t.Fatal("normal explicit closure failed", err)
	}
}

func TestSuperviseCanceledProbeRetainsReviewAndIndependentStop(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("could not start fixture", err)
	}
	entered := make(chan struct{})
	backend.readyHook = func(ctx context.Context) { close(entered); <-ctx.Done() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Second) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("supervision never admitted a scan")
	}
	cancel()
	err = waitSupervisionResult(t, done)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, nfsowner.ErrReviewRequired) || backend.running || backend.stopContextError != nil || !backend.retained || backend.stops != 1 {
		t.Fatal("late canceled probe published success or lost settlement authority", err)
	}
	if owner.Close(context.Background()) == nil || backend.releases != 0 || backend.stops != 1 {
		t.Fatal("uncertain scan allowed release or stop retry")
	}
}

func TestSuperviseRefusesBeforeAdmissionWithoutEffects(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, _ := nfsowner.NewQEMU(candidate, backend)
	for _, interval := range []time.Duration{-1, 0, time.Second - 1, time.Hour + 1} {
		if err := owner.Supervise(context.Background(), interval); !errors.Is(err, nfsowner.ErrInvalid) {
			t.Fatal("invalid idle interval admitted", interval, err)
		}
	}
	if err := owner.Supervise(context.Background(), time.Second); !errors.Is(err, nfsowner.ErrState) {
		t.Fatal("prepared lifetime supervised", err)
	}
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Supervise(ctx, time.Second); !errors.Is(err, context.Canceled) || backend.stops != 0 || !backend.running {
		t.Fatal("pre-admission cancellation touched the service", err)
	}
	if err := owner.Supervise(nil, time.Second); !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("nil context admitted", err)
	}
	copyOwner := *owner
	if err := copyOwner.Supervise(context.Background(), time.Second); !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("copied handle admitted", err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Supervise(context.Background(), time.Second); !errors.Is(err, nfsowner.ErrState) {
		t.Fatal("closed lifetime supervised", err)
	}
}

func TestSuperviseDisabledCancellationDoesNotStopOrRelease(t *testing.T) {
	candidate, backend := fixture(t, false)
	owner, _ := nfsowner.NewQEMU(candidate, backend)
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Hour) }()
	waitSupervisionExclusive(t, owner, done)
	cancel()
	if err := waitSupervisionResult(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	state, err := owner.Observe()
	if err != nil || state != nfsowner.Disabled || backend.starts != 0 || backend.stops != 0 || backend.releases != 0 || !backend.retained {
		t.Fatal("disabled supervision mutated service lifetime", state, err)
	}
	if err := owner.Close(context.Background()); err != nil || backend.retained {
		t.Fatal("disabled closure failed", err)
	}
}

func TestSuperviseFailedCancellationStopCannotRetryOrRelease(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, _ := nfsowner.NewQEMU(candidate, backend)
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.stopError = errors.New("uncertain synthetic stop")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Hour) }()
	waitSupervisionExclusive(t, owner, done)
	cancel()
	if err := waitSupervisionResult(t, done); !errors.Is(err, context.Canceled) || !errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("uncertain stop was not retained", err)
	}
	backend.stopError = nil
	if owner.Stop(context.Background()) == nil || owner.Close(context.Background()) == nil || backend.stops != 1 || backend.releases != 0 || !backend.retained {
		t.Fatal("later success erased original stop uncertainty")
	}
}

func waitSupervisionExclusive(t *testing.T, owner *nfsowner.Owner, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := owner.Observe(); errors.Is(err, nfsowner.ErrBusy) {
			return
		}
		select {
		case err := <-done:
			t.Fatal("supervision returned before owning the lifetime", err)
		case <-deadline.C:
			t.Fatal("supervision did not acquire the original lifetime")
		case <-time.After(time.Millisecond):
		}
	}
}

func waitSupervisionResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("supervision did not settle")
		return nil
	}
}

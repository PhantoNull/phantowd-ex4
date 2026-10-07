//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"errors"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func sharePinCloseBookkeepingPath(t *testing.T) *os.File {
	t.Helper()
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "share-pin-close-bookkeeping")
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// Only input-release bookkeeping is exercised: no healthy mount/roster lease
// is fabricated, verified or used to issue descriptors. Actual original-object
// QEMU admission and faulted mounted authority require separate guest coverage.
func TestSharePinCloseFailureKeepsHandoffReservedAndLaterInputsOpen(t *testing.T) {
	failed, later := sharePinCloseBookkeepingPath(t), sharePinCloseBookkeepingPath(t)
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	handoff := &ServiceHandoff{isolatedPins: 1, state: ServiceHandoffActive}
	pin := &ServiceSharePinsQEMU{handoff: handoff, roots: []shareRootQEMU{
		{id: "failed", file: failed}, {id: "later", file: later},
	}}
	if err := pin.Close(); !errors.Is(err, ErrHandoffReview) {
		t.Fatal("real input-close failure did not retain review", err)
	}
	if handoff.State() != ServiceHandoffReview || !errors.Is(handoff.Close(), ErrHandoffBusy) {
		t.Fatal("uncertain original input allowed handoff teardown")
	}
	if _, err := later.Stat(); err != nil {
		t.Fatal("release continued past the uncertain original", err)
	}
	if err := pin.Verify(); !errors.Is(err, ErrHandoffReview) {
		t.Fatal("failed closure did not fence verification", err)
	}
	if copies, err := pin.DuplicateRoots(); copies != nil || !errors.Is(err, ErrHandoffReview) {
		t.Fatal("failed closure issued new descriptors", err)
	}
	if err := pin.VerifyDeclaredRoots([]ServiceShare{{ID: "failed"}}); !errors.Is(err, ErrHandoffReview) {
		t.Fatal("caller declaration bypassed failed closure", err)
	}
	for range 3 {
		if err := pin.Close(); !errors.Is(err, ErrHandoffReview) {
			t.Fatal("repeated closure lost uncertainty", err)
		}
		if _, err := later.Stat(); err != nil {
			t.Fatal("repeated closure retried later input release", err)
		}
		if !errors.Is(handoff.Close(), ErrHandoffBusy) {
			t.Fatal("repeated closure released the handoff reservation")
		}
	}
}

func TestSharePinCloseFailureDoesNotRetryRepairedInputUnderConcurrentCalls(t *testing.T) {
	failed, later := sharePinCloseBookkeepingPath(t), sharePinCloseBookkeepingPath(t)
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	handoff := &ServiceHandoff{isolatedPins: 1, state: ServiceHandoffActive}
	pin := &ServiceSharePinsQEMU{handoff: handoff, roots: []shareRootQEMU{
		{id: "failed", file: failed}, {id: "later", file: later},
	}}
	if err := pin.Close(); !errors.Is(err, ErrHandoffReview) {
		t.Fatal("real original close failure was not quarantined", err)
	}
	// Controlled test-only substitution AFTER failure: it cannot repair the
	// lifetime or make the production Close retry/touch an unrelated object.
	replacement := sharePinCloseBookkeepingPath(t)
	pin.roots[0].file = replacement
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() {
			if err := pin.Close(); !errors.Is(err, ErrHandoffReview) {
				t.Error("concurrent Close lost quarantine", err)
			}
			if err := pin.Verify(); !errors.Is(err, ErrHandoffReview) {
				t.Error("concurrent verification revived release", err)
			}
			if copies, err := pin.DuplicateRoots(); copies != nil || !errors.Is(err, ErrHandoffReview) {
				t.Error("concurrent duplication revived release", err)
			}
			if !errors.Is(handoff.Close(), ErrHandoffBusy) {
				t.Error("concurrent handoff Close bypassed reservation")
			}
		})
	}
	callers.Wait()
	for _, file := range []*os.File{replacement, later} {
		if _, err := file.Stat(); err != nil {
			t.Fatal("quarantined release touched replacement or later input", err)
		}
	}
}

func TestSharePinCloseKnownInputsReleasesOnceWithoutGrantingMountAuthority(t *testing.T) {
	first, second := sharePinCloseBookkeepingPath(t), sharePinCloseBookkeepingPath(t)
	handoff := &ServiceHandoff{isolatedPins: 1, state: ServiceHandoffActive}
	pin := &ServiceSharePinsQEMU{handoff: handoff, roots: []shareRootQEMU{
		{id: "first", file: first}, {id: "second", file: second},
	}}
	if !errors.Is(handoff.Close(), ErrHandoffBusy) {
		t.Fatal("input reservation did not exclude handoff teardown")
	}
	for range 3 {
		if err := pin.Close(); err != nil {
			t.Fatal("known repeated input release was not idempotent", err)
		}
		for _, file := range []*os.File{first, second} {
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("successful input release left an original open", err)
			}
		}
		if err := pin.Verify(); !errors.Is(err, ErrHandoffUnavailable) {
			t.Fatal("closed inputs remained usable", err)
		}
		if copies, err := pin.DuplicateRoots(); copies != nil || !errors.Is(err, ErrHandoffUnavailable) {
			t.Fatal("closed lifetime issued new inputs", err)
		}
	}
	// Input bookkeeping released its reservation, but this deliberately absent
	// actual mount authority still cannot claim a settled handoff or any grant.
	if err := handoff.Close(); !errors.Is(err, ErrHandoffReview) {
		t.Fatal("absent mount authority was accepted after input release", err)
	}
}

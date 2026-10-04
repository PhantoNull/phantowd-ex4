//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func rootPinLeaseFixture(t *testing.T) (*MountedVolumeSetLease, *Owner, *modeledInspector) {
	t.Helper()
	owner, inspector := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	set, err := newMountedVolumeSet([]string{"alpha"}, []*Owner{owner})
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := set.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close(); _ = owner.Close() })
	return lease, owner, inspector
}

func TestVolumeRootPinOwnsIndependentDirectoriesAndBlocksGroupClose(t *testing.T) {
	lease, owner, _ := rootPinLeaseFixture(t)
	if pin, err := lease.PinVolumeRoot("unknown"); pin != nil || !errors.Is(err, ErrInvalid) || len(lease.rootPins) != 0 {
		t.Fatal("unknown member created a lease pin", err)
	}
	pin, err := lease.PinVolumeRoot("alpha")
	if err != nil {
		t.Fatal(err)
	}
	for sample := 0; sample < 100; sample++ {
		if err := pin.Verify(); err != nil {
			t.Fatal(err)
		}
		file, err := pin.OpenDirectory(".")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if len(lease.leases["alpha"].files) != 0 {
			t.Fatal("independent descriptor registered for a second close")
		}
	}
	if err := lease.Close(); !errors.Is(err, ErrBusy) || lease.closed {
		t.Fatal("lease released a live pin", err)
	}
	if _, err := json.Marshal(pin); err == nil {
		t.Fatal("root pin serializable")
	}
	if _, err := json.Marshal(VolumeRootPin{}); err == nil {
		t.Fatal("root pin value serializable")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pin.Release(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := pin.Verify(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("released pin revived", err)
	}
	if err := lease.Close(); err != nil || len(owner.leases) != 0 {
		t.Fatal("independent directory close caused lease close uncertainty", err)
	}
}

func TestVolumeRootPinDriftAndDrainAreStickyWithoutReleasingLease(t *testing.T) {
	for _, drift := range []string{"mount", "generation", "drain"} {
		t.Run(drift, func(t *testing.T) {
			lease, owner, inspector := rootPinLeaseFixture(t)
			pin, err := lease.PinVolumeRoot("alpha")
			if err != nil {
				t.Fatal(err)
			}
			switch drift {
			case "mount":
				inspector.wrongMount = true
			case "generation":
				owner.mu.Lock()
				owner.generation++
				owner.mu.Unlock()
			case "drain":
				if err := owner.Drain(); !errors.Is(err, ErrBusy) {
					t.Fatal(err)
				}
			}
			if err := pin.Verify(); !errors.Is(err, ErrReview) {
				t.Fatal("drift admitted", err)
			}
			if err := lease.Close(); !errors.Is(err, ErrBusy) {
				t.Fatal("review dropped lease pin", err)
			}
			if file, err := pin.OpenDirectory("."); file != nil || !errors.Is(err, ErrReview) {
				t.Fatal("review opened directory", err)
			}
			if err := pin.Release(); err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVolumeRootPinUncertainReferenceCloseRetainsClaim(t *testing.T) {
	lease, owner, inspector := rootPinLeaseFixture(t)
	pin, err := lease.PinVolumeRoot("alpha")
	if err != nil {
		t.Fatal(err)
	}
	root := owner.root.(*modeledRoot)
	inspector.observeHook = func(string) {
		if len(root.files) != 0 {
			_ = root.files[len(root.files)-1].Close()
			inspector.wrongMount = true
		}
	}
	if file, err := pin.OpenDirectory("."); file != nil || !errors.Is(err, ErrReview) || !pin.uncertain {
		t.Fatal("lost directory close was not retained", err)
	}
	for sample := 0; sample < 3; sample++ {
		if err := pin.Release(); !errors.Is(err, ErrReview) || len(lease.rootPins) != 1 {
			t.Fatal("uncertain release retried", err)
		}
		if err := lease.Close(); !errors.Is(err, ErrBusy) {
			t.Fatal("uncertainty released lease", err)
		}
	}
	// Test-only disposal of an already-closed synthetic reference, not recovery.
	delete(lease.rootPins, pin)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeRootPinRechecksUnselectedMemberBeforeDirectoryOpen(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, inspector := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"beta", "alpha"}, []*Owner{beta, alpha})
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := set.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	pin, err := lease.PinVolumeRoot("alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Release()
	root := alpha.root.(*modeledRoot)
	before := len(root.files)
	// wrongMount substitutes the same UUID beta already has in this modeled
	// inspector; change the observed mount ID instead of simulating no drift.
	inspector.targetExpected.MountID++
	if file, err := pin.OpenDirectory("."); file != nil || !errors.Is(err, ErrReview) {
		t.Fatal("unselected member drift admitted a selected directory", err)
	}
	if len(root.files) != before || alpha.State() != StateMounted || beta.State() != StateReviewRequired {
		t.Fatal("whole-roster check opened a directory or quarantined a healthy independent Owner")
	}
	if err := lease.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("whole-roster failure discarded a retained pin", err)
	}
}

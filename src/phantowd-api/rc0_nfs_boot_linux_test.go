// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
)

func TestRC0BootStopRequiresCurrentNFSLifetimeDrain(t *testing.T) {
	ctx := context.Background()
	control := &rc0BootStopAuthority{}
	control.nfs.Store(true)
	if control.accept(rc0DrainedStopRequest) || !errors.Is(control.quiescent(ctx), errRC0Review) {
		t.Fatal("accepted drain while startup was pending")
	}
	control.ready.Store(true)
	if control.accept(rc0StopRequest) || control.accept('X') || !errors.Is(control.quiescent(ctx), errRC0Review) {
		t.Fatal("accepted shutdown without client drain")
	}
	if !control.accept(rc0DrainedStopRequest) || control.quiescent(ctx) != nil || control.accept(rc0DrainedStopRequest) {
		t.Fatal("valid drain was refused or accepted more than once")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(control.quiescent(canceled), context.Canceled) {
		t.Fatal("accepted proof outside its shutdown context")
	}
	other := &rc0BootStopAuthority{}
	other.ready.Store(true)
	if other.accept(rc0DrainedStopRequest) || !other.accept(rc0StopRequest) || other.quiescent(ctx) == nil {
		t.Fatal("management-only operation became NFS drain authority")
	}
}

func TestRC0BootStopCanRetrySambaDrain(t *testing.T) {
	ctx := context.Background()
	control := &rc0BootStopAuthority{}
	pending := errors.New("Samba drain pending")
	calls := 0
	control.stopSamba = func(ctx context.Context) error {
		if err := control.authorizeSamba(ctx); err != nil {
			return err
		}
		calls++
		if calls == 1 {
			return pending
		}
		return nil
	}
	if control.accept(rc0StopRequest) || !errors.Is(control.drainSamba(ctx), errRC0Review) || calls != 0 {
		t.Fatal("authorized Samba drain before startup")
	}
	control.ready.Store(true)
	if !control.accept(rc0StopRequest) || !errors.Is(control.drainSamba(ctx), pending) ||
		!errors.Is(control.authorizeSamba(ctx), errRC0Review) {
		t.Fatal("failed drain retained shutdown authorization")
	}
	if !control.accept(rc0StopRequest) || control.drainSamba(ctx) != nil ||
		control.accept(rc0StopRequest) || calls != 2 {
		t.Fatal("successful drain did not keep exclusive shutdown authorization")
	}
}

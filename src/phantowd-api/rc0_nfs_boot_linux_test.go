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

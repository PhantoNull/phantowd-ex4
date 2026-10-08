//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestPlannedDaemonExitRequiresRuntimeAuthority(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if err := absent.RequestPlannedDaemonExitQEMU(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime accepted an exit request", err)
	}
}

func TestPlannedDaemonExitRefusesWithoutConsumingRequest(t *testing.T) {
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	if err := r.RequestPlannedDaemonExitQEMU(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent context entered runtime", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.RequestPlannedDaemonExitQEMU(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request entered runtime", err)
	}
	r.gate <- struct{}{}
	err := r.RequestPlannedDaemonExitQEMU(context.Background())
	<-r.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing request entered runtime", err)
	}
	for range 2 {
		if err := r.RequestPlannedDaemonExitQEMU(context.Background()); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("incomplete runtime accepted a signal", err)
		}
		if r.plannedExitAttempted || r.owner.review || r.closed || r.daemonAttempted || r.daemonPID != 0 || r.releaseErr != nil || len(r.gate) != 0 {
			t.Fatal("refusal changed unowned runtime lifetime")
		}
	}
	r.closed = true
	if err := r.RequestPlannedDaemonExitQEMU(context.Background()); !errors.Is(err, ErrReviewRequired) || r.plannedExitAttempted {
		t.Fatal("closed runtime consumed exit request", err)
	}
}

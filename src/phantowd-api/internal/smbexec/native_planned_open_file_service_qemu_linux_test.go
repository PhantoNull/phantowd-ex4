//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestPlannedOpenFileRefusesAbsentCanceledBusyAndUnstartedService(t *testing.T) {
	var absent *NativePlannedServiceQEMU
	if err := absent.StartHeldOpenFileQEMU(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent service admitted file holder:", err)
	}
	s := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.StartHeldOpenFileQEMU(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled file admission proceeded:", err)
	}
	s.gate <- struct{}{}
	err := s.StartHeldOpenFileQEMU(context.Background())
	<-s.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing file admission proceeded:", err)
	}
	if err := s.StartHeldOpenFileQEMU(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) || s.heldAttempted {
		t.Fatal("unstarted service attempted file admission:", err)
	}
}

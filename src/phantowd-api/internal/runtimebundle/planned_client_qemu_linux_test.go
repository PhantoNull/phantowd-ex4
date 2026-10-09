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

func TestPlannedHeldClientRefusesAbsentCanceledBusyAndUnstartedRuntime(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if err := absent.StartPlannedClientQEMU(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime started held client:", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.StartPlannedClientQEMU(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled held client admission proceeded:", err)
	}
	r.gate <- struct{}{}
	err := r.StartPlannedClientQEMU(context.Background())
	<-r.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing held client admission proceeded:", err)
	}
	if err := r.StartPlannedClientQEMU(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("unstarted runtime started held client:", err)
	}
	if observation, err := r.ObservePlannedHeldStopQEMU(context.Background()); observation != (PlannedHeldStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("unstarted runtime supplied held client evidence:", err)
	}
}

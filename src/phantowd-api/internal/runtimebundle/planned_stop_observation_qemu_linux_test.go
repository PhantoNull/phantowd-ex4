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

func TestPlannedStopObservationRefusesUnstartedAndCompetingRuntime(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if observed, err := absent.ObservePlannedStopQEMU(context.Background()); observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime supplied planned-stop evidence", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := r.ObservePlannedStopQEMU(ctx); observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation accessed runtime", err)
	}
	r.gate <- struct{}{}
	observed, err := r.ObservePlannedStopQEMU(context.Background())
	<-r.gate
	if observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing observation admitted", err)
	}
	if observed, err := r.ObservePlannedStopQEMU(context.Background()); observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("unstarted runtime claimed planned-stop evidence", err)
	}
}

func TestPlannedStopObservationDoesNotReplaceHeldClientContract(t *testing.T) {
	for _, r := range []*NativeSambaRuntimeQEMU{
		{closed: true},
		{daemonAttempted: true},     // Authentication-only, not the planned role.
		{plannedDataPrepared: true}, // Prepared inputs are not a started daemon.
		{plannedDataPrepared: true, daemonAttempted: true, clients: &processowner.PinnedSet{}},
		{plannedDataPrepared: true, daemonAttempted: true, clientsAttempted: true},
		{plannedDataPrepared: true, daemonAttempted: true, plannedClientAttempted: true},
		{plannedDataPrepared: true, daemonAttempted: true, pending: &processowner.CaptureOwner{}},
	} {
		r.owner, r.gate = &Owner{}, make(chan struct{}, 1)
		if observed, err := r.ObservePlannedStopQEMU(context.Background()); observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("wrong or incomplete runtime supplied planned-stop evidence", err)
		}
		if observed, err := r.ObserveNativeStopQEMU(context.Background()); observed != (NativeStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("planned observer weakened the held-client contract", err)
		}
	}
}

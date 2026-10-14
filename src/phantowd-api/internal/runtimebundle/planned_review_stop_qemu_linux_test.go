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

// Incomplete handles cannot launch/own a daemon. They test refusals only, not
// fabricated reviewed-stop success or physical/ARMv5 process qualification.
func TestPlannedReviewStopRequiresActualReviewedRuntime(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if observed, err := absent.ObservePlannedReviewStopQEMU(context.Background()); observed != (PlannedReviewStopObservationQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime supplied reviewed-stop evidence", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := r.ObservePlannedReviewStopQEMU(ctx); observed != (PlannedReviewStopObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation entered runtime", err)
	}
	r.gate <- struct{}{}
	observed, err := r.ObservePlannedReviewStopQEMU(context.Background())
	<-r.gate
	if observed != (PlannedReviewStopObservationQEMU{}) || !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing observation entered runtime", err)
	}
	if observed, err := r.ObservePlannedReviewStopQEMU(context.Background()); observed != (PlannedReviewStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("unstarted runtime supplied reviewed-stop evidence", err)
	}
}

func TestPlannedReviewStopDoesNotReclassifyNormalOrIncompleteRoles(t *testing.T) {
	for _, r := range []*NativeSambaRuntimeQEMU{
		{closed: true},
		{plannedDataPrepared: true},
		{plannedDataPrepared: true, daemonAttempted: true},
		{plannedDataPrepared: true, daemonAttempted: true, daemonPID: 2},
		{plannedDataPrepared: true, daemonAttempted: true, daemonPID: 2, clientsAttempted: true},
		{plannedDataPrepared: true, daemonAttempted: true, daemonPID: 2, pending: &processowner.CaptureOwner{}},
	} {
		r.owner, r.gate = &Owner{review: true}, make(chan struct{}, 1)
		if observed, err := r.ObservePlannedReviewStopQEMU(context.Background()); observed != (PlannedReviewStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("incomplete reviewed role supplied stopped evidence", err)
		}
		// These are still invalid/unstarted roles; the new observer must not
		// weaken the normal observer or the older two-client contract.
		if observed, err := r.ObservePlannedStopQEMU(context.Background()); observed != (PlannedStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("review witness changed normal-stop admission", err)
		}
		if observed, err := r.ObserveNativeStopQEMU(context.Background()); observed != (NativeStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("review witness changed held-client admission", err)
		}
	}
}

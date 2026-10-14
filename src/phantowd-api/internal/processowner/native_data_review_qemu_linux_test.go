//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"testing"
)

// No process, ready authority or descriptor is fabricated. Positive reviewed
// stop/retention evidence must come from the actual disposable ARMv5 daemon.
func TestNativeDataReviewStopRequiresOwnedReviewedGeneration(t *testing.T) {
	var absent *PinnedSet
	if observed, err := absent.ObserveNativeDataReviewStopQEMU(context.Background()); observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent authority supplied reviewed-stop evidence", err)
	}
	set := &PinnedSet{gate: make(chan struct{}, 1), set: &Set{}}
	if observed, err := set.ObserveNativeDataReviewStopQEMU(context.Background()); observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("unowned set supplied reviewed-stop evidence", err)
	}
}

func TestNativeDataReviewStopRefusesCanceledBusyAndClosedLifetime(t *testing.T) {
	set := &PinnedSet{gate: make(chan struct{}, 1), set: &Set{}}
	if observed, err := set.ObserveNativeDataReviewStopQEMU(nil); observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent context accessed retained inputs", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := set.ObserveNativeDataReviewStopQEMU(ctx); observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation accessed retained inputs", err)
	}
	set.gate <- struct{}{}
	observed, err := set.ObserveNativeDataReviewStopQEMU(context.Background())
	<-set.gate
	if observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, ErrBusy) {
		t.Fatal("competing observation accessed retained inputs", err)
	}
	set.closed = true
	if observed, err := set.ObserveNativeDataReviewStopQEMU(context.Background()); observed != (NativeDataReviewStopObservationQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed lifetime supplied retention evidence", err)
	}
}

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

func TestNativeStopObservationRefusesUnavailableCanceledAndBusy(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if observed, err := absent.ObserveNativeStopQEMU(context.Background()); observed != (NativeStopObservationQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime supplied stop evidence", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := r.ObserveNativeStopQEMU(ctx); observed != (NativeStopObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation accessed runtime", err)
	}
	r.gate <- struct{}{}
	observed, err := r.ObserveNativeStopQEMU(context.Background())
	<-r.gate
	if observed != (NativeStopObservationQEMU{}) || !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing observation admitted", err)
	}
	if observed, err := r.ObserveNativeStopQEMU(context.Background()); observed != (NativeStopObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("unstarted runtime claimed stop evidence", err)
	}
}

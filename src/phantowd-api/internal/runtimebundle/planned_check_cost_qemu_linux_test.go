//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPlannedCheckCostsKeepOrderAndFreezeOnlyOnFailure(t *testing.T) {
	cause := errors.Join(context.DeadlineExceeded, ErrReviewRequired)
	clock := plannedDataCostClockQEMU{start: time.Now().Add(-time.Second)}
	for i := 0; i < 13; i++ {
		clock.recordCheck(time.Duration(i+1)*time.Millisecond + 500*time.Microsecond)
	}
	annotated := clock.annotate(cause)
	clock.recordCheck(time.Millisecond) // A later mutation cannot change the copy.
	got := ObservePlannedCheckCostsQEMU(annotated)
	if !got.Present || got.Checks != 13 {
		t.Fatal("missing fixed check sequence", got)
	}
	for i, ms := range got.MS {
		if ms != int64(i+1) {
			t.Fatal("lost check order or rounding", got)
		}
	}
	if !errors.Is(annotated, context.DeadlineExceeded) || !errors.Is(annotated, ErrReviewRequired) {
		t.Fatal("timing replaced the original cause")
	}
	if clock.annotate(nil) != nil || ObservePlannedCheckCostsQEMU(nil).Present || ObservePlannedCheckCostsQEMU(cause).Present {
		t.Fatal("success or untyped error invented check measurements")
	}
}

func TestPlannedCheckCostsRefuseIncompleteOrImpossibleSamples(t *testing.T) {
	cause := context.DeadlineExceeded
	legacy := plannedDataCostClockQEMU{start: time.Now().Add(-time.Second), checks: 1, checkTime: time.Millisecond}
	if !ObservePlannedDataCostsQEMU(legacy.annotate(cause)).Present || ObservePlannedCheckCostsQEMU(legacy.annotate(cause)).Present {
		t.Fatal("legacy aggregate was lost or invented an individual sample")
	}
	for _, duration := range []time.Duration{-time.Nanosecond, 181 * time.Second} {
		clock := plannedDataCostClockQEMU{start: time.Now().Add(-time.Second)}
		clock.recordCheck(duration)
		if ObservePlannedCheckCostsQEMU(clock.annotate(cause)).Present {
			t.Fatal("invalid duration emitted", duration)
		}
	}
	clock := plannedDataCostClockQEMU{start: time.Now().Add(-time.Second)}
	for i := 0; i < 14; i++ {
		clock.recordCheck(time.Millisecond)
	}
	if ObservePlannedCheckCostsQEMU(clock.annotate(cause)).Present {
		t.Fatal("too many check samples admitted")
	}
}

func TestPlannedCheckCostsRejectUnboundSamplesWithoutChangingCause(t *testing.T) {
	base := PlannedDataCostObservationQEMU{Present: true, Checks: 1, CheckMS: 1, TotalMS: 2}
	for _, checks := range []PlannedCheckCostObservationQEMU{
		{}, {Present: true}, {Present: true, Checks: 14},
		{Present: true, Checks: 2, MS: [13]int64{1}},
		{Present: true, Checks: 1, MS: [13]int64{-1}},
		{Present: true, Checks: 1, MS: [13]int64{2}},
		{Present: true, Checks: 1, MS: [13]int64{1, 1}},
		{Present: true, Checks: 1}, // Sum does not match the original aggregate.
	} {
		err := &plannedDataCostFailureQEMU{cause: context.DeadlineExceeded, costs: base, checks: checks}
		if ObservePlannedCheckCostsQEMU(err).Present || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("unbound timing sequence admitted or cause lost", checks)
		}
	}
	if ObservePlannedCheckCostsQEMU((*plannedDataCostFailureQEMU)(nil)).Present {
		t.Fatal("typed nil supplied measurements")
	}
	clock := plannedDataCostClockQEMU{start: time.Now()}
	clock.recordCheck(0)
	if got := ObservePlannedCheckCostsQEMU(clock.annotate(context.Canceled)); !got.Present || got.Checks != 1 || got.MS[0] != 0 {
		t.Fatal("zero rounded measurement was confused with an absent sample", got)
	}
}

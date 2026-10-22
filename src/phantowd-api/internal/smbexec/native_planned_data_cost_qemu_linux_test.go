//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNativePlannedAccessCostsCopyRefusalWithoutInventingCause(t *testing.T) {
	clock := nativePlannedAccessCostClockQEMU{start: time.Now().Add(-time.Second), steps: 3,
		at: [3]time.Duration{10 * time.Millisecond, 30 * time.Millisecond, 35 * time.Millisecond}}
	costs := clock.observe("after-runtime")
	clock.at[0] = 0 // The captured values do not retain a mutable clock.
	cause := errors.New("redacted")
	err := &nativePlannedDataFailureQEMU{stage: "after-runtime", cause: cause, refusalContext: "deadline", costs: costs}
	got := ObserveNativePlannedDataCostsQEMU(err)
	if !got.Present || got.BeforeMS != 10 || got.RuntimeMS != 20 || got.AfterMS != 5 || got.TotalMS < 1000 {
		t.Fatal("coordinator costs not copied at refusal", got)
	}
	if !errors.Is(err, cause) || errors.Is(err, context.DeadlineExceeded) || err.Error() == cause.Error() {
		t.Fatal("timing changed or exposed original error")
	}
	if ObserveNativePlannedDataCostsQEMU(nil).Present || ObserveNativePlannedDataCostsQEMU(cause).Present ||
		ObserveNativePlannedDataCostsQEMU((*nativePlannedDataFailureQEMU)(nil)).Present {
		t.Fatal("missing refusal invented costs")
	}
}

func TestNativePlannedAccessCostsRefuseIncompleteAndInvalidStages(t *testing.T) {
	for stage, steps := range map[string]int{"before-runtime": 1, "runtime": 2, "after-runtime": 3} {
		clock := nativePlannedAccessCostClockQEMU{start: time.Now().Add(-time.Second), steps: steps}
		for i := 0; i < steps; i++ {
			clock.at[i] = time.Duration(i+1) * time.Millisecond
		}
		if !clock.observe(stage).Present {
			t.Fatal("reached fixed stage lost", stage)
		}
		clock.steps++
		if clock.observe(stage).Present {
			t.Fatal("wrong stage count admitted", stage)
		}
	}
	for _, clock := range []nativePlannedAccessCostClockQEMU{
		{}, {start: time.Now(), steps: 4},
		{start: time.Now().Add(time.Second), steps: 1},
		{start: time.Now().Add(-181 * time.Second), steps: 1},
		{start: time.Now().Add(-time.Second), steps: 2, at: [3]time.Duration{2, 1}},
		{start: time.Now().Add(-time.Second), steps: 1, at: [3]time.Duration{-1}},
	} {
		if clock.observe("before-runtime").Present || clock.observe("runtime").Present || clock.observe("invalid").Present {
			t.Fatal("invalid timeline admitted")
		}
	}
	for _, costs := range []NativePlannedDataCostsObservationQEMU{
		{}, {Present: true, BeforeMS: -1}, {Present: true, TotalMS: 180001},
		{Present: true, BeforeMS: 1}, {Present: true, RuntimeMS: 1, TotalMS: 1},
		{Present: true, AfterMS: 1, TotalMS: 1},
	} {
		err := &nativePlannedDataFailureQEMU{stage: "before-runtime", cause: context.Canceled, costs: costs}
		if ObserveNativePlannedDataCostsQEMU(err).Present || !errors.Is(err, context.Canceled) {
			t.Fatal("incoherent timeline admitted or original cause lost", costs)
		}
	}
}

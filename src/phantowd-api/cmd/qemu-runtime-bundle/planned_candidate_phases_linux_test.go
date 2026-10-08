//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestPlannedCandidateIndependentWorkloadsDoNotSpendEachOthersBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var completed int
		workload := func(ctx context.Context) error {
			time.Sleep(20 * time.Second)
			if err := ctx.Err(); err != nil {
				return err
			}
			completed++
			return nil
		}
		if err := runPlannedCandidatePhasesQEMU(context.Background(), workload, workload); err != nil || completed != 2 {
			t.Fatalf("two individually bounded workloads: completed=%d error=%v", completed, err)
		}
	})
}

func TestPlannedCandidateUncertainOrExpiredFirstPhaseCannotProceedOrRetry(t *testing.T) {
	uncertain := errors.New("uncertain original fixture operation")
	for _, cause := range []string{"uncertain", "expired", "parent-canceled"} {
		t.Run(cause, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				var first, second int
				want := uncertain
				err := runPlannedCandidatePhasesQEMU(parent, func(context.Context) error {
					first++
					switch cause {
					case "uncertain":
						return uncertain
					case "expired":
						want = context.DeadlineExceeded
						time.Sleep(31 * time.Second)
					case "parent-canceled":
						want = context.Canceled
						cancel()
					}
					return nil // Late nil is not evidence of healthy completion.
				}, func(context.Context) error { second++; return nil })
				if !errors.Is(err, want) || first != 1 || second != 0 {
					t.Fatalf("failed first phase proceeded/retried: first=%d second=%d error=%v", first, second, err)
				}
			})
		})
	}
}

func TestPlannedCandidateParentDeadlineStillBoundsBothPhases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		parent, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		var completed int
		workload := func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Second):
				completed++
				return nil
			}
		}
		if err := runPlannedCandidatePhasesQEMU(parent, workload, workload); !errors.Is(err, context.DeadlineExceeded) || completed != 1 || time.Since(started) != 35*time.Second {
			t.Fatalf("parent deadline detached: completed=%d elapsed=%v error=%v", completed, time.Since(started), err)
		}
	})
}

func TestPlannedCandidatePreparedPhaseCannotReportLateSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var original context.Context
		err := runPlannedCandidatePhasesQEMU(context.Background(), func(ctx context.Context) error {
			original = ctx
			return nil
		}, func(context.Context) error {
			if !errors.Is(original.Err(), context.Canceled) {
				t.Fatal("completed original phase still owns a live timer")
			}
			time.Sleep(31 * time.Second)
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("late second phase accepted: %v", err)
		}
	})
}

func TestPlannedCandidateInvalidStagesRefuseBeforeAnyEffect(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, scenario := range []string{"no-parent", "no-candidate", "no-prepared", "canceled-parent"} {
		t.Run(scenario, func(t *testing.T) {
			var effects int
			parent := context.Background()
			candidate := func(context.Context) error { effects++; return nil }
			prepared := candidate
			switch scenario {
			case "no-parent":
				parent = nil
			case "no-candidate":
				candidate = nil
			case "no-prepared":
				prepared = nil
			case "canceled-parent":
				parent = canceled
			}
			if err := runPlannedCandidatePhasesQEMU(parent, candidate, prepared); err == nil || effects != 0 {
				t.Fatalf("invalid stages produced effects: effects=%d error=%v", effects, err)
			}
		})
	}
}

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

// The actual coordinator fixture calls this same phase runner. These are
// orchestration tests, not fabricated identity, runtime or session authority.
func TestNativeCoordinatorPreparationCannotSpendRevocationBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		begin := time.Now()
		var prepared context.Context
		completed := 0
		err := runNativeCoordinatorPhasesQEMU(context.Background(), func(ctx context.Context) error {
			prepared = ctx
			time.Sleep(19 * time.Second)
			return ctx.Err()
		}, func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != 45*time.Second {
				t.Errorf("revocation inherits preparation cost: remaining=%v", time.Until(deadline))
			}
			if !errors.Is(prepared.Err(), context.Canceled) {
				t.Error("preparation context remains live after handoff")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(40 * time.Second):
				completed++
				return nil
			}
		})
		if err != nil || completed != 1 || time.Since(begin) != 59*time.Second {
			t.Fatalf("separately bounded workloads failed: completed=%d elapsed=%v error=%v", completed, time.Since(begin), err)
		}
	})
}

func TestNativeCoordinatorFailedPreparationNeverProceedsOrRetries(t *testing.T) {
	uncertain := errors.New("uncertain fixed fixture operation")
	for _, cause := range []string{"uncertain", "expired", "parent-canceled", "uncertain-and-expired"} {
		t.Run(cause, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				first, second := 0, 0
				var preparation context.Context
				want := uncertain
				err := runNativeCoordinatorPhasesQEMU(parent, func(ctx context.Context) error {
					preparation = ctx
					first++
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) != 20*time.Second {
						t.Error("preparation does not have its own fixed 20-second bound")
					}
					switch cause {
					case "uncertain":
						return uncertain
					case "expired", "uncertain-and-expired":
						time.Sleep(21 * time.Second)
						want = context.DeadlineExceeded
						if cause == "uncertain-and-expired" {
							return uncertain
						}
					case "parent-canceled":
						want = context.Canceled
						cancel()
					}
					return nil // A late successful return must not admit revocation.
				}, func(context.Context) error { second++; return nil })
				if !errors.Is(err, want) || first != 1 || second != 0 || preparation.Err() == nil {
					t.Fatalf("failed preparation proceeded/retried: first=%d second=%d error=%v context=%v", first, second, err, preparation.Err())
				}
				if cause == "uncertain-and-expired" && !errors.Is(err, uncertain) {
					t.Fatal("deadline erased the original uncertainty")
				}
			})
		})
	}
}

func TestNativeCoordinatorParentBoundsBothPhases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		begin := time.Now()
		parent, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		first, second := 0, 0
		err := runNativeCoordinatorPhasesQEMU(parent, func(ctx context.Context) error {
			first++
			time.Sleep(19 * time.Second)
			return ctx.Err()
		}, func(ctx context.Context) error {
			second++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != 16*time.Second {
				t.Error("shorter parent no longer bounds revocation")
			}
			<-ctx.Done()
			return nil // Late nil cannot turn the parent's deadline into success.
		})
		if !errors.Is(err, context.DeadlineExceeded) || first != 1 || second != 1 || time.Since(begin) != 35*time.Second {
			t.Fatalf("parent detached: first=%d second=%d elapsed=%v error=%v", first, second, time.Since(begin), err)
		}
	})
}

func TestNativeCoordinatorRevocationCannotReturnLateSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revocation context.Context
		calls := 0
		err := runNativeCoordinatorPhasesQEMU(context.Background(), func(context.Context) error { return nil }, func(ctx context.Context) error {
			revocation = ctx
			calls++
			time.Sleep(46 * time.Second)
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || revocation.Err() == nil {
			t.Fatalf("late revocation accepted/retried: calls=%d error=%v", calls, err)
		}
	})
}

func TestNativeCoordinatorInvalidPhasesRefuseBeforeEffects(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, scenario := range []string{"no-parent", "no-preparation", "no-revocation", "canceled-parent"} {
		t.Run(scenario, func(t *testing.T) {
			effects := 0
			parent := context.Background()
			prepare := func(context.Context) error { effects++; return nil }
			revoke := prepare
			switch scenario {
			case "no-parent":
				parent = nil
			case "no-preparation":
				prepare = nil
			case "no-revocation":
				revoke = nil
			case "canceled-parent":
				parent = canceled
			}
			if err := runNativeCoordinatorPhasesQEMU(parent, prepare, revoke); err == nil || effects != 0 {
				t.Fatalf("invalid phase dispatch: effects=%d error=%v", effects, err)
			}
		})
	}
}

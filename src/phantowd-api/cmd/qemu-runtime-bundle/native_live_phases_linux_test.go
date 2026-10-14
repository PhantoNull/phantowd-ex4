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

// The native campaign calls this same runner. Model the observed completed
// 44.714s continuity phase plus fresh authentication, not fabricated authority.
func TestNativeLivePhasesCompletedContinuityLeavesFullAuthenticationBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		var live context.Context
		completed := false
		err := runNativeLivePhasesQEMU(context.Background(), func(ctx context.Context) error {
			live = ctx
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) != 45*time.Second {
				t.Fatal("continuity lacks the original fixed 45-second budget")
			}
			time.Sleep(44714 * time.Millisecond)
			return ctx.Err()
		}, func(ctx context.Context) error {
			if live.Err() != context.Canceled {
				t.Fatal("completed continuity timer remains live")
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) != 15*time.Second {
				t.Fatal("authentication inherits continuity cost or has an unbounded context")
			}
			time.Sleep(10 * time.Second)
			completed = true
			return ctx.Err()
		})
		if err != nil || !completed || time.Since(started) != 54714*time.Millisecond {
			t.Fatalf("completed continuity starved authentication: completed=%t elapsed=%v err=%v", completed, time.Since(started), err)
		}
	})
}

func TestNativeLivePhasesUncertainOrLateContinuityNeverAuthenticates(t *testing.T) {
	uncertain := errors.New("uncertain continuity result")
	for _, scenario := range []string{"uncertain", "expired", "uncertain-and-expired", "parent-canceled"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := [2]int{}
				var observed context.Context
				want := uncertain
				err := runNativeLivePhasesQEMU(parent, func(ctx context.Context) error {
					observed = ctx
					calls[0]++
					switch scenario {
					case "uncertain":
						return uncertain
					case "expired", "uncertain-and-expired":
						time.Sleep(45 * time.Second)
						want = context.DeadlineExceeded
						if scenario == "uncertain-and-expired" {
							return uncertain
						}
					case "parent-canceled":
						cancel()
						want = context.Canceled
					}
					return nil // A late nil cannot grant the second phase.
				}, func(context.Context) error { calls[1]++; return nil })
				if !errors.Is(err, want) || calls != [2]int{1, 0} || observed.Err() == nil {
					t.Fatalf("failed continuity entered authentication/retried: calls=%v err=%v", calls, err)
				}
				if scenario == "uncertain-and-expired" && !errors.Is(err, uncertain) {
					t.Fatal("deadline erased the original uncertainty")
				}
			})
		})
	}
}

func TestNativeLivePhasesAuthenticationIsBoundedAndNeverRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := [2]int{}
		var authentication context.Context
		err := runNativeLivePhasesQEMU(context.Background(), func(context.Context) error {
			calls[0]++
			return nil
		}, func(ctx context.Context) error {
			calls[1]++
			authentication = ctx
			time.Sleep(15 * time.Second)
			return nil // Exact deadline is not timely successful completion.
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != [2]int{1, 1} || authentication.Err() == nil {
			t.Fatalf("late authentication accepted/retried: calls=%v err=%v", calls, err)
		}
	})
}

func TestNativeLivePhasesParentBoundsBothPhasesAndValues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type fixtureKey struct{}
		parent, cancel := context.WithTimeout(context.WithValue(context.Background(), fixtureKey{}, "fixed-fixture"), 50*time.Second)
		defer cancel()
		started := time.Now()
		err := runNativeLivePhasesQEMU(parent, func(ctx context.Context) error {
			if ctx.Value(fixtureKey{}) != "fixed-fixture" {
				t.Fatal("continuity detached from original parent values")
			}
			time.Sleep(44 * time.Second)
			return ctx.Err()
		}, func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != 6*time.Second || ctx.Value(fixtureKey{}) != "fixed-fixture" {
				t.Fatal("authentication detached from the shorter parent")
			}
			<-ctx.Done()
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 50*time.Second {
			t.Fatal("shorter parent was renewed or late success accepted", err)
		}
	})
}

func TestNativeLivePhasesAuthenticationUncertaintyAndCancellationRetainFailure(t *testing.T) {
	uncertain := errors.New("uncertain authentication result")
	for _, scenario := range []string{"uncertain", "uncertain-and-expired", "parent-canceled"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := [2]int{}
				var observed context.Context
				want := uncertain
				err := runNativeLivePhasesQEMU(parent, func(context.Context) error {
					calls[0]++
					return nil
				}, func(ctx context.Context) error {
					calls[1]++
					observed = ctx
					if scenario == "parent-canceled" {
						cancel()
						want = context.Canceled
						return nil
					}
					if scenario == "uncertain-and-expired" {
						time.Sleep(15 * time.Second)
						want = context.DeadlineExceeded
					}
					return uncertain
				})
				if !errors.Is(err, want) || calls != [2]int{1, 1} || observed.Err() == nil {
					t.Fatal("authentication uncertainty was accepted/retried", calls, err)
				}
				if scenario == "uncertain-and-expired" && !errors.Is(err, uncertain) {
					t.Fatal("authentication deadline erased its original error")
				}
			})
		})
	}
}

func TestNativeLivePhasesInvalidInputsHaveNoEffects(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, scenario := range []string{"no-parent", "no-live", "no-authentication", "canceled-parent"} {
		t.Run(scenario, func(t *testing.T) {
			effects := 0
			parent := context.Background()
			live := func(context.Context) error { effects++; return nil }
			authenticate := live
			switch scenario {
			case "no-parent":
				parent = nil
			case "no-live":
				live = nil
			case "no-authentication":
				authenticate = nil
			case "canceled-parent":
				parent = canceled
			}
			if err := runNativeLivePhasesQEMU(parent, live, authenticate); err == nil || effects != 0 {
				t.Fatal("invalid/canceled fixture performed work", err, effects)
			}
		})
	}
}

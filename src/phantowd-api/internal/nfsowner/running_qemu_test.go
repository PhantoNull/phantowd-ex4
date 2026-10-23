//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"testing"
)

func TestRunningOwnerStopsBeforeOriginalInputsAreReleased(t *testing.T) {
	candidate, backend := lifetimeInputs(t, true)
	if err := ExerciseRunningQEMU(candidate, backend.bound); err != nil {
		t.Fatal(err)
	}
	owner, _ := NewQEMU(candidate, backend)
	ctx := context.Background()
	if err := owner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := owner.Observe(); state != Running || !backend.retained || !backend.running {
		t.Fatal("running inputs not retained", state)
	}
	if err := owner.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := owner.Observe(); state != Stopped || !backend.retained || backend.running {
		t.Fatal("stop consumed inputs or left server running", state)
	}
	if err := owner.Stop(ctx); err != nil || backend.stops != 1 {
		t.Fatal("duplicate stop repeated settlement", err)
	}
	if err := owner.Start(ctx); !errors.Is(err, ErrState) {
		t.Fatal("stopped owner restarted", err)
	}
	if err := owner.Close(ctx); err != nil || backend.retained || backend.releases != 1 {
		t.Fatal("verified close did not release", err)
	}
}

func TestDisabledOwnerNeverStartsOrStopsAServer(t *testing.T) {
	candidate, backend := preparedInputs(t)
	owner, _ := NewQEMU(candidate, backend)
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := owner.Observe(); state != Disabled || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("empty policy controlled a server", state)
	}
	if err := owner.Close(context.Background()); err != nil || backend.retained || backend.stops != 0 {
		t.Fatal("disabled closure did not release safely", err)
	}
}

func TestUncertainStartSettlesOnceAndRetainsReview(t *testing.T) {
	for _, phase := range []string{"start", "ready", "post-start-inputs"} {
		t.Run(phase, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			backend.fail = phase
			if phase == "post-start-inputs" {
				backend.hook = func(p string) {
					if p == "ready" {
						backend.fail = "inputs"
					}
				}
			}
			if err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) || backend.running || backend.stops != 1 || !backend.retained {
				t.Fatal("uncertain start did not settle and retain inputs", err)
			}
			backend.fail, backend.hook = "", nil
			for _, call := range []func(context.Context) error{owner.Start, owner.Stop, owner.Close} {
				if err := call(context.Background()); !errors.Is(err, ErrReviewRequired) {
					t.Fatal("review was reopened", err)
				}
			}
			if backend.starts != 1 || backend.stops != 1 || backend.releases != 0 {
				t.Fatal("review retried cleanup or released inputs")
			}
		})
	}
}

func TestLifecycleCancellationKeepsInputsForReview(t *testing.T) {
	for _, phase := range []string{"inputs", "start", "ready", "stop", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := owner.Start
			if phase == "stop" || phase == "stopped" {
				if err := owner.Start(ctx); err != nil {
					t.Fatal(err)
				}
				call = owner.Stop
			}
			backend.hook = func(p string) {
				if p == phase {
					cancel()
				}
			}
			if err := call(ctx); !errors.Is(err, ErrReviewRequired) || !errors.Is(err, context.Canceled) || !backend.retained {
				t.Fatal("late cancellation lost review or inputs", err)
			}
			if phase != "inputs" && (backend.running || backend.stops != 1) {
				t.Fatal("accepted effects were not settled once")
			}
			if phase == "inputs" && (backend.starts != 0 || backend.stops != 0) {
				t.Fatal("preflight failure controlled a server")
			}
		})
	}
}

func TestRunningCloseSettlesBeforeReleaseAndKeepsUncertainty(t *testing.T) {
	for _, phase := range []string{"", "stop", "stopped"} {
		t.Run("close-"+phase, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			if err := owner.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			backend.fail = phase
			err := owner.Close(context.Background())
			if phase == "" {
				if err != nil || backend.running || backend.retained || backend.stops != 1 {
					t.Fatal("live close did not settle before release", err)
				}
			} else if !errors.Is(err, ErrReviewRequired) || !backend.retained || backend.releases != 0 || backend.stops != 1 {
				t.Fatal("uncertain stop released inputs", err)
			}
		})
	}
}

func TestPartialStartKeepsInputsWhenSettlementFails(t *testing.T) {
	for _, phase := range []string{"stop", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			backend.fail = "ready"
			backend.hook = func(p string) {
				if p == "stop" {
					backend.fail = phase
				}
			}
			if err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) || !backend.retained || backend.releases != 0 || backend.stops != 1 {
				t.Fatal("uncertain compensation released inputs", err)
			}
			backend.fail, backend.hook = "", nil
			if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) || backend.stops != 1 || backend.releases != 0 {
				t.Fatal("restoration retried compensation", err)
			}
		})
	}
}

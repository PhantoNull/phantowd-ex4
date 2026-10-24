//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func freshCheck(t *testing.T, owner *Owner) func(context.Context) error {
	t.Helper()
	checker, ok := any(owner).(interface{ Check(context.Context) error })
	if !ok {
		t.Fatal("NFS lifetime lacks fresh checking")
	}
	return checker.Check
}

func TestFreshCheckPreservesHealthyLifetime(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "running"}[enabled], func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, enabled)
			if enabled {
				if err := ExerciseCheckedQEMU(candidate, backend.bound); err != nil {
					t.Fatal(err)
				}
			}
			owner, _ := NewQEMU(candidate, backend)
			check := freshCheck(t, owner)
			if err := owner.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			var calls []string
			backend.hook = func(phase string) { calls = append(calls, phase) }
			probe, state, starts := "stopped", Disabled, 0
			if enabled {
				probe, state, starts = "ready", Running, 1
			}
			if err := check(context.Background()); err != nil || !reflect.DeepEqual(calls, []string{"inputs", probe, "inputs"}) {
				t.Fatal("fresh check did not bracket the live probe", err, calls)
			}
			if got, _ := owner.Observe(); got != state || !backend.retained || backend.running != enabled || backend.starts != starts || backend.stops != 0 || backend.releases != 0 {
				t.Fatal("healthy check changed the lifetime")
			}
			backend.hook = nil
			if err := owner.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFreshCheckFailureSettlesOnlyRunningAndRetainsReview(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, phase := range []string{"inputs-before", "probe", "inputs-after"} {
			t.Run(map[bool]string{false: "disabled-", true: "running-"}[enabled]+phase, func(t *testing.T) {
				candidate, backend := lifetimeInputs(t, enabled)
				owner, _ := NewQEMU(candidate, backend)
				check := freshCheck(t, owner)
				if err := owner.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				inputs := 0
				probe := "stopped"
				if enabled {
					probe = "ready"
				}
				backend.hook = func(name string) {
					if name == "inputs" {
						inputs++
					}
					if phase == "probe" && name == probe || name == "inputs" && (phase == "inputs-before" && inputs == 1 || phase == "inputs-after" && inputs == 2) {
						backend.fail = name
					}
				}
				err := check(context.Background())
				stops := 0
				if enabled {
					stops = 1
				}
				if !errors.Is(err, ErrReviewRequired) || strings.Contains(err.Error(), "backend details") || backend.running || !backend.retained || backend.stops != stops || backend.releases != 0 {
					t.Fatal("failed check lost retained review or settlement", err)
				}
				backend.fail, backend.hook = "", nil
				for _, operation := range []func(context.Context) error{check, owner.Start, owner.Stop, owner.Close} {
					if err := operation(context.Background()); !errors.Is(err, ErrReviewRequired) {
						t.Fatal("restoration revived a reviewed lifetime", err)
					}
				}
				if backend.stops != stops || backend.releases != 0 || !backend.retained {
					t.Fatal("review retried cleanup or released inputs")
				}
			})
		}
	}
}

func TestFreshCheckLateCancellationSettlesIndependently(t *testing.T) {
	for _, phase := range []string{"inputs-before", "ready", "inputs-after"} {
		t.Run(phase, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			check := freshCheck(t, owner)
			if err := owner.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inputs := 0
			backend.hook = func(name string) {
				if name == "inputs" {
					inputs++
				}
				if phase == name || name == "inputs" && (phase == "inputs-before" && inputs == 1 || phase == "inputs-after" && inputs == 2) {
					cancel()
				}
			}
			if err := check(ctx); !errors.Is(err, ErrReviewRequired) || !errors.Is(err, context.Canceled) || backend.running || backend.stops != 1 || backend.releases != 0 || !backend.retained {
				t.Fatal("late cancellation suppressed independent settlement", err)
			}
		})
	}
}

func TestFreshCheckUncertainSettlementCannotBeRetried(t *testing.T) {
	for _, failure := range []string{"stop", "stopped"} {
		t.Run(failure, func(t *testing.T) {
			candidate, backend := lifetimeInputs(t, true)
			owner, _ := NewQEMU(candidate, backend)
			check := freshCheck(t, owner)
			if err := owner.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			backend.fail = "ready"
			backend.hook = func(phase string) {
				if phase == "stop" {
					backend.fail = failure
				}
			}
			if err := check(context.Background()); !errors.Is(err, ErrReviewRequired) || backend.running != (failure == "stop") || !backend.retained || backend.stops != 1 || backend.releases != 0 {
				t.Fatal("uncertain settlement lost the original lifetime", err)
			}
			backend.fail, backend.hook = "", nil
			for _, call := range []func(context.Context) error{check, owner.Stop, owner.Close} {
				if err := call(context.Background()); !errors.Is(err, ErrReviewRequired) || backend.stops != 1 || backend.releases != 0 {
					t.Fatal("uncertain settlement was retried", err)
				}
			}
		})
	}
}

func TestFreshCheckRefusesBeforeBackendActivity(t *testing.T) {
	candidate, backend := lifetimeInputs(t, true)
	owner, _ := NewQEMU(candidate, backend)
	check := freshCheck(t, owner)
	called := false
	backend.hook = func(string) { called = true }
	if err := check(context.Background()); !errors.Is(err, ErrState) || called {
		t.Fatal("prepared lifetime was checked", err)
	}
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	called = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	copy := *owner
	for _, tc := range []struct {
		check func(context.Context) error
		ctx   context.Context
		want  error
	}{{check, ctx, context.Canceled}, {check, nil, ErrInvalid}, {freshCheck(t, &copy), context.Background(), ErrInvalid}, {freshCheck(t, nil), context.Background(), ErrInvalid}, {freshCheck(t, &Owner{}), context.Background(), ErrInvalid}} {
		if err := tc.check(tc.ctx); !errors.Is(err, tc.want) || called {
			t.Fatal("refused check reached backend", err)
		}
	}
	backend.hook = nil
	if err := owner.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("stopped lifetime was checked", err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("closed lifetime was checked", err)
	}
}

func TestFreshCheckOwnsTheCompleteTransition(t *testing.T) {
	candidate, backend := lifetimeInputs(t, true)
	owner, _ := NewQEMU(candidate, backend)
	check := freshCheck(t, owner)
	if err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	backend.hook = func(string) { once.Do(func() { close(entered); <-release }) }
	go func() { done <- check(context.Background()) }()
	<-entered
	for _, operation := range []func(context.Context) error{check, owner.Start, owner.Stop, owner.Close} {
		if err := operation(context.Background()); !errors.Is(err, ErrBusy) {
			t.Error("concurrent operation entered the check", err)
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	backend.hook = nil
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

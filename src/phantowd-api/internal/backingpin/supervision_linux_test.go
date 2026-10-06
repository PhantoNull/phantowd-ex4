//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func startLifecycleSupervisor(t *testing.T, owner *writableOwner) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- owner.supervise(ctx) }()
	t.Cleanup(func() { cancel() })
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		owner.mu.Lock()
		accepted := owner.supervising
		owner.mu.Unlock()
		if accepted {
			return cancel, done
		}
		select {
		case err := <-done:
			t.Fatal("supervision refused", err)
		case <-deadline.C:
			t.Fatal("supervision did not acquire lifecycle")
		case <-time.After(time.Millisecond):
		}
	}
}

func awaitLifecycleSupervisor(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(8 * time.Second):
		t.Fatal("supervision did not settle")
		return nil
	}
}

func TestWritableSupervisionRejectsUnacceptedRequestsWithoutEffects(t *testing.T) {
	owner, backend := lifecycleOwner(t)
	if !errors.Is(owner.supervise(nil), ErrInvalid) || !errors.Is(owner.supervise(context.Background()), ErrInvalid) {
		t.Fatal("invalid/prepared supervision admitted")
	}
	if backend.startCalls != 0 || backend.stopCalls != 0 || owner.released {
		t.Fatal("supervision implicitly started/closed prepared owner")
	}
	if err := owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(owner.supervise(ctx), ErrUnavailable) || backend.stopCalls != 0 || owner.released || owner.supervising {
		t.Fatal("unaccepted cancel consumed active lifecycle")
	}
	if err := owner.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWritableSupervisionExclusiveCancellationAndReview(t *testing.T) {
	for _, kind := range []string{"cancel", "cancel-uncertain", "drift", "drift-uncertain", "exit", "observation", "file-close"} {
		t.Run(kind, func(t *testing.T) {
			owner, backend := lifecycleOwner(t)
			ctx := context.Background()
			if err := owner.start(ctx); err != nil {
				t.Fatal(err)
			}
			cancel, done := startLifecycleSupervisor(t, owner)
			for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close, func() error { return owner.supervise(ctx) }} {
				if !errors.Is(op(), ErrBusy) {
					t.Fatal("concurrent lifecycle bypassed supervisor")
				}
			}
			owner.mu.Lock()
			switch kind {
			case "cancel-uncertain":
				backend.stopError = ErrUnavailable
			case "drift", "drift-uncertain":
				owner.check = func() error { return ErrUnavailable }
				if kind == "drift-uncertain" {
					backend.stopError = ErrUnavailable
				}
			case "exit":
				backend.active = false
			case "observation":
				backend.runningError = ErrUnavailable
			case "file-close":
				if err := owner.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			owner.mu.Unlock()
			if kind == "cancel" || kind == "cancel-uncertain" || kind == "file-close" {
				cancel()
			}
			err := awaitLifecycleSupervisor(t, done)
			if kind == "cancel" {
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReview) || owner.phase != writableClosed || !owner.released {
					t.Fatal("verified cancellation did not close", err)
				}
			} else {
				if !errors.Is(err, ErrReview) || owner.phase != writableReview {
					t.Fatal("fault not reviewed", err)
				}
				if kind == "cancel-uncertain" && !errors.Is(err, context.Canceled) {
					t.Fatal("lost cancellation cause", err)
				}
				if kind == "cancel-uncertain" || kind == "drift-uncertain" || kind == "file-close" {
					if owner.released || owner.pin.consumer != owner {
						t.Fatal("uncertain supervision dropped claims")
					}
				}
				owner.check = func() error { return nil }
				backend.stopError, backend.runningError = nil, nil
				for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close, func() error { return owner.supervise(ctx) }} {
					if !errors.Is(op(), ErrReview) {
						t.Fatal("restoration revived reviewed supervisor")
					}
				}
			}
			if backend.stopCalls != 1 || owner.supervising {
				t.Fatal("stop retry or stranded lifecycle reservation")
			}
			if kind != "file-close" && !backend.stopWithLiveReference {
				t.Fatal("stop did not precede reference release")
			}
		})
	}
}

func TestWritableSupervisionCancellationDuringScanUsesFreshStopContext(t *testing.T) {
	owner, backend := lifecycleOwner(t)
	if err := owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	owner.check = func() error { once.Do(func() { close(entered); <-release }); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.supervise(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("immediate scan missing")
	}
	cancel()
	// The first scan finishes before accepted cancellation performs one stop.
	close(release)
	if err := awaitLifecycleSupervisor(t, done); !errors.Is(err, context.Canceled) || errors.Is(err, ErrReview) {
		t.Fatal("cancellation stranded healthy lifecycle", err)
	}
	if !owner.released || backend.stopCalls != 1 || !backend.stopWithLiveReference {
		t.Fatal("cancel did not confirm stop before release")
	}
	if backend.stopContextError != nil || !backend.stopContextDeadline {
		t.Fatal("accepted cancellation reused the canceled request for stop")
	}
}

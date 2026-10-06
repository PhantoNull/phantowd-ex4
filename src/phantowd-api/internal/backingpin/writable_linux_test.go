//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
)

type lifecycleBackend struct {
	startCalls, stopCalls               int
	active                              bool
	startError, runningError, stopError error
	file                                *os.File
	onStart                             func()
	stopWithLiveReference               bool
	stopContextError                    error
	stopContextDeadline                 bool
}

func (b *lifecycleBackend) start(_ context.Context, file *os.File) error {
	b.startCalls++
	b.file = file
	b.active = true
	if b.onStart != nil {
		b.onStart()
	}
	return b.startError
}
func (b *lifecycleBackend) running(context.Context) (bool, error) { return b.active, b.runningError }
func (b *lifecycleBackend) stop(ctx context.Context) error {
	b.stopCalls++
	b.stopContextError = ctx.Err()
	_, b.stopContextDeadline = ctx.Deadline()
	if b.file != nil {
		_, err := b.file.Stat()
		b.stopWithLiveReference = err == nil
	}
	if b.stopError != nil {
		return b.stopError
	}
	b.active = false
	return nil
}

// Native lifecycle seam only: not a qualified filesystem/descriptor admission.
// Actual real-Root/RW descriptor matching remains mandatory in the QEMU fixture.
func lifecycleOwner(t *testing.T) (*writableOwner, *lifecycleBackend) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "synthetic-")
	if err != nil {
		t.Fatal(err)
	}
	b := &lifecycleBackend{}
	o := &writableOwner{file: f, pin: &Pin{}, backend: b, check: func() error { return nil }}
	o.pin.consumer = o
	t.Cleanup(func() { _ = f.Close() })
	return o, b
}

func TestWritableLifecycleNormalAndExclusiveClaim(t *testing.T) {
	o, b := lifecycleOwner(t)
	ctx := context.Background()
	if err := o.pin.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("claimed pin prematurely closed", err)
	}
	if err := o.observe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); !errors.Is(err, ErrBusy) {
		t.Fatal("active consumer prematurely closed", err)
	}
	if err := o.observe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if b.startCalls != 1 || b.stopCalls != 1 || !b.stopWithLiveReference || !o.released || !o.pin.closed {
		t.Fatal("stop/release ordering")
	}
	if err := o.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	if b.stopCalls != 1 {
		t.Fatal("cleanup retried")
	}
	if err := o.start(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("restart allowed", err)
	}
	if _, err := json.Marshal(o); err == nil {
		t.Fatal("owner serializable")
	}
	if _, err := json.Marshal(writableOwner{}); err == nil {
		t.Fatal("owner value serializable")
	}
}

func TestWritableLifecycleFailureQuarantinesAndStopsBeforeRelease(t *testing.T) {
	for _, kind := range []string{"preflight", "start", "readiness", "post-start", "drift", "exit", "observe", "stop", "close"} {
		t.Run(kind, func(t *testing.T) {
			o, b := lifecycleOwner(t)
			ctx := context.Background()
			switch kind {
			case "preflight":
				o.check = func() error { return ErrUnavailable }
			case "start":
				b.startError = ErrUnavailable
			case "readiness":
				b.runningError = ErrUnavailable
			case "post-start":
				b.onStart = func() { o.check = func() error { return ErrUnavailable } }
			}
			startErr := o.start(ctx)
			if kind == "preflight" || kind == "start" || kind == "readiness" || kind == "post-start" {
				if !errors.Is(startErr, ErrReview) {
					t.Fatal(startErr)
				}
			} else {
				if startErr != nil {
					t.Fatal(startErr)
				}
				switch kind {
				case "drift":
					o.check = func() error { return ErrUnavailable }
				case "exit":
					b.active = false
				case "observe":
					b.runningError = ErrUnavailable
				case "stop":
					b.stopError = ErrUnavailable
				case "close":
					if err := o.file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if kind == "stop" || kind == "close" {
					err = o.stop(ctx)
				} else {
					err = o.observe(ctx)
				}
				if !errors.Is(err, ErrReview) {
					t.Fatal(err)
				}
			}
			if o.phase != writableReview {
				t.Fatal("failure not quarantined")
			}
			stopCalls := b.stopCalls
			if kind == "preflight" {
				if stopCalls != 0 || b.startCalls != 0 {
					t.Fatal("preflight side effect")
				}
			} else if stopCalls != 1 {
				t.Fatal("not one stop attempt", stopCalls)
			}
			if kind == "stop" || kind == "close" {
				if o.released || o.pin.consumer != o || o.pin.closed {
					t.Fatal("uncertainty released backing")
				}
				if err := o.pin.Close(); !errors.Is(err, ErrBusy) {
					t.Fatal("uncertainty claim bypass", err)
				}
			} else if !o.released {
				t.Fatal("verified stopped references not released")
			}
			for _, op := range []func() error{func() error { return o.start(ctx) }, func() error { return o.observe(ctx) }, func() error { return o.stop(ctx) }, o.close} {
				if err := op(); !errors.Is(err, ErrReview) {
					t.Fatal("review bypass", err)
				}
			}
			if b.stopCalls != stopCalls {
				t.Fatal("uncertain stop automatically retried")
			}
		})
	}
}

func TestWritableLifecycleCancellationAndConcurrentStop(t *testing.T) {
	o, b := lifecycleOwner(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.start(ctx); !errors.Is(err, ErrUnavailable) || b.startCalls != 0 {
		t.Fatal("cancel started backend", err)
	}
	if err := o.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := o.stop(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if b.stopCalls != 1 || !o.released {
		t.Fatal("concurrent stop did not serialize")
	}
	if _, err := newWritableOwner(nil, nil, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestWritableTypedNilBackendHasNoEffects(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "nil-backend-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pin := &Pin{}
	var backend *lifecycleBackend
	if owner, err := newWritableOwner(pin, file, backend, newBackingUseOwner()); owner != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil must refuse before filesystem checks: %v", err)
	}
	if pin.consumer != nil {
		t.Fatal("invalid backend claimed Pin")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("invalid backend consumed file", err)
	}
}

// Native state-machine composition, not actual mount/descriptor admission.
// An observed identity loss plus uncertain stop must retain authority even if
// both the checker and backend subsequently report that they are healthy.
func TestWritableDriftAndUncertainStopCannotBeRevived(t *testing.T) {
	o, b := lifecycleOwner(t)
	ctx := context.Background()
	if err := o.start(ctx); err != nil {
		t.Fatal(err)
	}
	o.check = func() error { return ErrUnavailable }
	b.stopError = ErrUnavailable
	if err := o.observe(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("drift/uncertain stop not quarantined", err)
	}
	if !b.active || b.stopCalls != 1 || !b.stopWithLiveReference || o.released || o.pin.consumer != o {
		t.Fatal("uncertain drift lost live references or stop ordering")
	}
	o.check = func() error { return nil }
	b.stopError = nil
	for _, op := range []func() error{func() error { return o.start(ctx) }, func() error { return o.observe(ctx) }, func() error { return o.stop(ctx) }, o.close} {
		if err := op(); !errors.Is(err, ErrReview) {
			t.Fatal("restoration bypassed review", err)
		}
	}
	if b.stopCalls != 1 || !b.active || o.released {
		t.Fatal("restoration retried stop or released references")
	}
	if err := o.pin.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("restoration bypassed retained pin", err)
	}
	if _, err := o.file.Stat(); err != nil {
		t.Fatal("restoration lost data reference", err)
	}
}

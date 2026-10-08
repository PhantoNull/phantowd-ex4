//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// This is precisely the inner-close step AFTER verified runtime closure.
// No runtime is fabricated, admitted, invoked or reported healthy by these
// tests. They qualify post-runtime bookkeeping over real files, not execution,
// process retirement, kernel EIO, QEMU worker faults or durable recovery.
func TestNativeBackendInnerCloseFailureSurvivesPublicCloseAndReplacement(t *testing.T) {
	original := closeFixtureFile(t)
	b := &NativeBackendQEMU{inner: &Backend{config: original}}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	first := b.closeInnerAfterRuntimeQEMU()
	b.mu.Unlock()
	if !errors.Is(first, os.ErrClosed) || !errors.Is(first, runtimebundle.ErrReviewRequired) {
		t.Fatal("real inner-close fault was not observed", first)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := b.Close(); err != first {
			t.Fatal("public repeated close erased the inner failure", err)
		}
	}
	if b.inner == nil {
		t.Fatal("failed inner close discarded its original bookkeeping")
	}
	// Test-only repair cannot revive this lifetime or close an unrelated file.
	replacement := closeFixtureFile(t)
	calls := 0
	b.mu.Lock()
	b.inner = &Backend{config: replacement, runner: runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	})}
	b.mu.Unlock()
	account := serviceaccounts.Account{ID: "qpmanaged", Name: "qpmanaged", UID: 2000, GID: 2000, State: serviceaccounts.Disabled}
	if !nativeFixtureAccountQEMU(account) || !validAccount(account) || !validObservedAccount(account) {
		t.Fatal("account would refuse before the terminal-lifetime fence")
	}
	ctx := context.Background()
	for _, operation := range []func() error{
		func() error { _, err := b.Observe(ctx, account); return err },
		func() error { _, err := b.ObserveAccounts(ctx, []serviceaccounts.Account{account}); return err },
		func() error { _, err := b.ObserveAccounts(ctx, nil); return err },
		func() error { return b.CreateDisabled(ctx, account) },
		func() error { return b.SetPasswordDisabled(ctx, account, []byte("native-close-fixture-only-password")) },
		func() error { return b.Enable(ctx, account) },
		func() error { return b.Disable(ctx, account) },
		func() error { _, err := b.ObserveNativeSessionPairQEMU(ctx); return err },
		func() error {
			return b.VerifyNativePeerSessionQEMU(ctx, NativeSessionPairQEMU{
				backend: b,
				target:  smbStatusSession{SessionID: "negative-only-target"},
				peer:    smbStatusSession{SessionID: "negative-only-peer"},
			})
		},
	} {
		if err := operation(); err == nil {
			t.Fatal("closed native wrapper admitted an operation")
		}
	}
	if calls != 0 {
		t.Fatal("closed native wrapper invoked its runner")
	}
	if err := b.Close(); err != first {
		t.Fatal("replacement erased the original close failure", err)
	}
	if _, err := replacement.Stat(); err != nil {
		t.Fatal("repeated close touched the replacement", err)
	}
}

func TestNativeSessionObservationRejectsPreCanceledContextBeforeDispatch(t *testing.T) {
	// Negative-only command boundary; no admitted runtime or healthy session
	// witness is constructed. An open real file lets the test reach the context
	// fence rather than failing at absent configuration.
	calls := 0
	backend := &Backend{config: closeFixtureFile(t), runner: runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	})}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	native := &NativeBackendQEMU{inner: backend}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sessions, err := native.readNativeSessionsQEMU(ctx)
	if sessions != nil || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("pre-canceled session observation dispatched or lost refusal: sessions=%v error=%v calls=%d", sessions, err, calls)
	}
}

func TestNativeSessionObservationRejectsClosedInnerBeforeDispatch(t *testing.T) {
	// Actual regular-file close failure leaves the original inner bookkeeping
	// available, but its terminal lifetime must still forbid a status worker.
	original := closeFixtureFile(t)
	calls := 0
	backend := &Backend{config: original, runner: runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	})}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	first := backend.Close()
	if !errors.Is(first, os.ErrClosed) {
		t.Fatal("closed-file fault did not reach the inner lifecycle", first)
	}
	native := &NativeBackendQEMU{inner: backend}
	sessions, err := native.readNativeSessionsQEMU(context.Background())
	if sessions != nil || !errors.Is(err, ErrInvalid) || calls != 0 {
		t.Fatalf("closed inner dispatched a session worker: sessions=%v error=%v calls=%d", sessions, err, calls)
	}
	if backend.Close() != first || native.closed || native.inner != backend {
		t.Fatal("read-only refusal changed terminal bookkeeping or retried close")
	}
}

func TestNativeBackendInnerCloseFailureSerializesRepeatedClose(t *testing.T) {
	original := closeFixtureFile(t)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	b := &NativeBackendQEMU{inner: &Backend{config: original}}
	b.mu.Lock()
	first := b.closeInnerAfterRuntimeQEMU()
	b.mu.Unlock()
	if !errors.Is(first, os.ErrClosed) {
		t.Fatal(first)
	}
	var group sync.WaitGroup
	for attempt := 0; attempt < 32; attempt++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := b.Close(); err != first {
				t.Error("concurrent close forgot inner failure", err)
			}
			if _, err := b.ObserveAccounts(context.Background(), nil); err == nil {
				t.Error("closed wrapper accepted empty observation")
			}
		}()
	}
	group.Wait()
}

func TestNativeBackendInnerSuccessfulCloseRemainsIdempotent(t *testing.T) {
	b := &NativeBackendQEMU{inner: &Backend{config: closeFixtureFile(t)}}
	b.mu.Lock()
	err := b.closeInnerAfterRuntimeQEMU()
	b.mu.Unlock()
	if err != nil || b.Close() != nil || (*NativeBackendQEMU)(nil).Close() != nil {
		t.Fatal("normal repeated close changed", err)
	}
	if _, err := b.ObserveAccounts(context.Background(), nil); err == nil {
		t.Fatal("normally closed wrapper accepted observation")
	}
}

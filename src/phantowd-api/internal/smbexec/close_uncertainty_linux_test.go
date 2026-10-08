//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// Real regular-file closure only. This seam neither admits configuration nor
// launches a command; production New/openConfig ownership checks are unchanged.
func closeFixtureFile(t *testing.T) *os.File {
	t.Helper()
	name := filepath.Join(t.TempDir(), "config-reference")
	if err := os.WriteFile(name, []byte("close fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestBackendCloseFailureIsTerminalAndNeverClosesReplacement(t *testing.T) {
	original := closeFixtureFile(t)
	calls := 0
	b := &Backend{config: original, runner: runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	})}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	first := b.Close()
	if !errors.Is(first, os.ErrClosed) {
		t.Fatal("real closed-file fault was not observed", first)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := b.Close(); err != first {
			t.Fatal("repeated close lost its terminal error", err)
		}
	}
	// Test-only repair cannot revive the lifetime or close an unrelated object.
	replacement := closeFixtureFile(t)
	b.mu.Lock()
	b.config = replacement
	b.mu.Unlock()
	ctx := context.Background()
	account := serviceaccounts.Account{ID: "alice", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	if !validAccount(account) || !validObservedAccount(account) || !smbprovision.ValidPassword([]byte("close-fixture-only-password")) {
		t.Fatal("command fixtures would refuse before the terminal-state fence")
	}
	for _, operation := range []func() error{
		func() error { _, err := b.Observe(ctx, account); return err },
		func() error { _, err := b.ObserveAccounts(ctx, []serviceaccounts.Account{account}); return err },
		func() error { _, err := b.ObserveAccounts(ctx, nil); return err },
		func() error { return b.CreateDisabled(ctx, account) },
		func() error { return b.SetPasswordDisabled(ctx, account, []byte("close-fixture-only-password")) },
		func() error { return b.Enable(ctx, account) },
		func() error { return b.Disable(ctx, account) },
	} {
		if err := operation(); err == nil {
			t.Fatal("terminal backend admitted a command or empty observation")
		}
	}
	if calls != 0 {
		t.Fatal("terminal backend invoked its runner")
	}
	if err := b.Close(); err != first {
		t.Fatal("repair erased the original close error", err)
	}
	if _, err := replacement.Stat(); err != nil {
		t.Fatal("repeated close touched the replacement", err)
	}
}

func TestBackendCloseFailureSerializesConcurrentObservers(t *testing.T) {
	file := closeFixtureFile(t)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	b := &Backend{config: file}
	first := b.Close()
	if !errors.Is(first, os.ErrClosed) {
		t.Fatal(first)
	}
	var joined sync.WaitGroup
	for attempt := 0; attempt < 32; attempt++ {
		joined.Add(1)
		go func() {
			defer joined.Done()
			if err := b.Close(); err != first {
				t.Error("concurrent close lost quarantine", err)
			}
			if _, err := b.ObserveAccounts(context.Background(), nil); err == nil {
				t.Error("concurrent empty observation reported success")
			}
		}()
	}
	joined.Wait()
}

func TestBackendSuccessfulCloseRemainsIdempotent(t *testing.T) {
	b := &Backend{config: closeFixtureFile(t)}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal("normal repeated close changed", err)
	}
	if err := (*Backend)(nil).Close(); err != nil {
		t.Fatal("nil close changed", err)
	}
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// This non-root model never executes Samba or validates configuration trust.
// Constructor ownership and actual native wrapper binding have separate tests.
func nativeBudgetFixtureBackend(t *testing.T, runner commandRunner) *Backend {
	t.Helper()
	config, err := os.CreateTemp(t.TempDir(), "native-budget-")
	if err != nil {
		t.Fatal(err)
	}
	backend := &Backend{config: config, runner: runner}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	return backend
}

// Model measured worker latency at the real composite helper called by the
// native adapter. Command order, contexts and the inventory parser are real;
// this is not configuration admission, journal or ARMv5 qualification.
func TestNativeDisableBudgetsCompleteWorkerSequence(t *testing.T) {
	account := serviceaccounts.Account{ID: "first", Name: "qpmanaged", UID: 2000, GID: 2000, State: serviceaccounts.Disabled}
	var calls []string
	statusReads := 0
	backend := nativeBudgetFixtureBackend(t, runnerFunc(func(ctx context.Context, executable string, args []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		calls = append(calls, filepath.Base(executable))
		if executable == smbpasswdPath {
			return nil, nil
		}
		if executable != smbstatusPath && executable != smbcontrolPath {
			t.Fatal("unexpected native revocation worker")
		}
		// Local ARMv5 workers measured 2.46-2.68 seconds. Four complete
		// workers plus polling cannot fit in the former ten-second total.
		timer := time.NewTimer(2600 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		if executable == smbcontrolPath {
			if !slices.Equal(args, []string{"-s", configArgument, "smbd", "logoff-user", account.Name}) {
				t.Fatal("control escaped exact target identity")
			}
			return nil, nil
		}
		statusReads++
		output := string(testSMBStatusJSON(statusReads == 1))
		// Use the exact native fixture identity without changing the real
		// parser or its independent peer session/generation record.
		return []byte(strings.ReplaceAll(output, "alice", account.Name)), nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := backend.disableWithProfile(ctx, account, nativeQEMURevocationProfile); err != nil {
		t.Fatalf("individually bounded native workers exhausted composite budget: %v; calls=%v", err, calls)
	}
	if !slices.Equal(calls, []string{"smbpasswd", "smbstatus", "smbcontrol", "smbstatus", "smbstatus"}) || statusReads != 3 {
		t.Fatalf("native revoke lost verification or retried a mutation: %v / %d", calls, statusReads)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDisableCapsControlWorkerSeparately(t *testing.T) {
	account := serviceaccounts.Account{ID: "first", Name: "qpmanaged", UID: 2000, GID: 2000, State: serviceaccounts.Disabled}
	controls := 0
	backend := nativeBudgetFixtureBackend(t, runnerFunc(func(ctx context.Context, executable string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		if executable == smbstatusPath {
			return []byte(strings.ReplaceAll(string(testSMBStatusJSON(true)), "alice", account.Name)), nil
		}
		if executable == smbcontrolPath {
			controls++
			deadline, ok := ctx.Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 0 || remaining > 4*time.Second {
				t.Errorf("native control inherited aggregate budget: %v", remaining)
			}
			return nil, errors.New("modeled uncertain control; do not retry")
		}
		return nil, nil
	}))
	if err := backend.disableWithProfile(context.Background(), account, nativeQEMURevocationProfile); !errors.Is(err, ErrUnavailable) || controls != 1 {
		t.Fatalf("uncertain native control escaped fail-closed/no-retry: %v / %d", err, controls)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDisableRejectsSuccessfulInventoryAfterItsOwnDeadline(t *testing.T) {
	statusReads := 0
	var returned []byte
	backend := nativeBudgetFixtureBackend(t, runnerFunc(func(ctx context.Context, executable string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		switch executable {
		case smbpasswdPath:
			return nil, nil
		case smbstatusPath:
			statusReads++
			if ctx.Err() != nil {
				t.Fatal("inventory was already expired before modeled worker")
			}
			// Model a worker that returns successful exit/output only after
			// its own status deadline. The parent remains independently live.
			<-ctx.Done()
			returned = testSMBStatusJSON(false)
			return returned, nil
		default:
			t.Fatal("late inventory caused another control or mutation")
			return nil, ErrUnavailable
		}
	}))
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	err := backend.Disable(ctx, account)
	if !errors.Is(err, ErrUnavailable) || statusReads != 1 || ctx.Err() != nil {
		t.Fatalf("late child status escaped its deadline: error=%v reads=%d parent=%v", err, statusReads, ctx.Err())
	}
	for _, value := range returned {
		if value != 0 {
			t.Fatal("expired inventory output was not cleared")
		}
	}
}

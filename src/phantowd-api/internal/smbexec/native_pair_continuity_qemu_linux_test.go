//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNativeSessionPairContinuityRefusesReplacementTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	// Replace only the external Samba status boundary. The real adapter keeps
	// its pinned configuration and validates the complete private inventory.
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, _ []string, _ *os.File, _ []byte, capture bool) ([]byte, error) {
		if executable != smbstatusPath || !capture {
			t.Fatal("continuity dispatched a mutation or a different command")
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); err != nil {
		t.Fatal("original two sessions refused:", err)
	}
	fixture = strings.ReplaceAll(fixture, "123456789", "123456790")
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); err == nil {
		t.Fatal("replacement target generation was accepted as original continuity")
	}
}

func TestNativeSessionPairContinuityPreservesCancellationWithoutDispatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	dispatched := false
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		dispatched = true
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dispatched = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := native.VerifyNativeSessionPairQEMU(ctx, pair); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was lost:", err)
	}
	if dispatched {
		t.Fatal("pre-canceled continuity dispatched a status worker")
	}
}

func TestNativeSessionPairContinuityRequiresCompleteOriginalInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	original := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	fixture := original
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, args []string, _ *os.File, input []byte, capture bool) ([]byte, error) {
		if executable != smbstatusPath || len(args) != 3 || args[0] != "-j" || args[1] != "-s" || args[2] != configArgument || len(input) != 0 || !capture {
			t.Fatal("continuity escaped the fixed read-only status command")
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, changed string }{
		{"target-generation", strings.ReplaceAll(original, "123456789", "123456790")},
		{"peer-generation", strings.ReplaceAll(original, "987654321", "987654322")},
		{"target-pid", strings.ReplaceAll(original, "1001", "1003")},
		{"peer-pid", strings.ReplaceAll(original, "1002", "1003")},
		{"target-session", strings.ReplaceAll(original, "1000000000001", "1000000000003")},
		{"peer-session", strings.ReplaceAll(original, "1000000000002", "1000000000003")},
		{"wrong-user", strings.ReplaceAll(original, "qpmanaged", "foreign")},
		{"missing-target", strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")},
		{"no-sessions", `{"sessions":{}}`},
		{"null-sessions", `{"sessions":null}`},
		{"duplicate-keys", `{"sessions":{},"sessions":{}}`},
		{"unqualified-generation", strings.ReplaceAll(original, "987654321", "18446744073709551615")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture = test.changed
			want := ErrNativeSessionPairChangedQEMU
			switch test.name {
			case "null-sessions", "duplicate-keys", "unqualified-generation":
				want = ErrUnavailable
			}
			if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); !errors.Is(err, want) {
				t.Fatal("replacement or incomplete inventory admitted:", err)
			}
		})
	}
	fixture = original
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); err != nil {
		t.Fatal("unchanged complete inventory refused:", err)
	}
}

func TestNativeSessionPairContinuityRefusesInvalidWitnessWithoutDispatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	dispatched := false
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		dispatched = true
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dispatched = false
	var absent *NativeBackendQEMU
	for _, operation := range []func() error{
		func() error { return absent.VerifyNativeSessionPairQEMU(context.Background(), pair) },
		func() error { return native.VerifyNativeSessionPairQEMU(context.Background(), NativeSessionPairQEMU{}) },
		func() error {
			return (&NativeBackendQEMU{inner: backend}).VerifyNativeSessionPairQEMU(context.Background(), pair)
		},
		func() error { return native.VerifyNativeSessionPairQEMU(nil, pair) },
	} {
		if err := operation(); !errors.Is(err, ErrInvalid) {
			t.Fatal("absent, foreign or invalid observation admitted:", err)
		}
	}
	if dispatched {
		t.Fatal("invalid continuity dispatched a status worker")
	}
}

func TestNativeSessionPairContinuityRefusesLateSuccessAfterCancellation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	var cancelOnReply context.CancelFunc
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		if cancelOnReply != nil {
			cancelOnReply()
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelOnReply = cancel
	if err := native.VerifyNativeSessionPairQEMU(ctx, pair); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("late successful status reply became continuity:", err)
	}
}

func TestNativeSessionPairContinuityDistinguishesChangedInventoryFromUnavailable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	var commandErr error
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		return []byte(fixture), commandErr
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture = strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); !errors.Is(err, ErrNativeSessionPairChangedQEMU) {
		t.Fatal("complete changed inventory was indistinguishable from failed observation:", err)
	}
	commandErr = errors.New("private external command failure")
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativeSessionPairChangedQEMU) {
		t.Fatal("failed command was accepted as observed session change:", err)
	}
	commandErr = nil
	fixture = `{"sessions":null}`
	if err := native.VerifyNativeSessionPairQEMU(context.Background(), pair); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativeSessionPairChangedQEMU) {
		t.Fatal("incomplete inventory was accepted as observed session change:", err)
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNativeRevokedPairUsesOneFreshCompleteInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	original := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	peerOnly := strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	fixture, calls := original, 0
	var pinned *os.File
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, args []string, config *os.File, input []byte, capture bool) ([]byte, error) {
		calls++
		if executable != smbstatusPath || !slices.Equal(args, []string{"-j", "-p", "-s", configArgument}) || config != pinned || len(input) != 0 || !capture {
			t.Fatal("revoked-pair observation escaped original read-only status authority")
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	pinned = backend.config
	native := &NativeBackendQEMU{inner: backend}
	pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture, calls = peerOnly, 0
	if err := native.VerifyNativeRevokedPairQEMU(context.Background(), pair); err != nil || calls != 1 {
		t.Fatalf("same peer and absent original target require one complete observation: calls=%d err=%v", calls, err)
	}
	// The next invocation MUST read again, not reuse the previous success.
	fixture, calls = original, 0
	if err := native.VerifyNativeRevokedPairQEMU(context.Background(), pair); err == nil || calls != 1 {
		t.Fatalf("returned target was hidden by cached success: calls=%d err=%v", calls, err)
	}
}

func TestNativeRevokedPairRefusesIncompleteOrChangedPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	original := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	peer := strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	fixture, calls := original, 0
	var commandErr error
	var cancelReply context.CancelFunc
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		calls++
		if cancelReply != nil {
			cancelReply()
		}
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
	for _, test := range []struct{ name, output string }{
		{"original-target-still-present", original},
		{"replacement-target", strings.ReplaceAll(original, "123456789", "123456790")},
		{"no-sessions", `{"sessions":{}}`},
		{"missing-sessions", `{}`},
		{"null-sessions", `{"sessions":null}`},
		{"invalid-json", `{"sessions":`},
		{"duplicate-key", `{"sessions":{},"sessions":{}}`},
		{"changed-peer-generation", strings.ReplaceAll(peer, "987654321", "987654322")},
		{"changed-peer-pid", strings.ReplaceAll(peer, "1002", "1003")},
		{"changed-peer-session", strings.ReplaceAll(peer, "1000000000002", "1000000000003")},
		{"wrong-user", strings.ReplaceAll(peer, "qpsecond", "foreign")},
		{"unqualified-peer-generation", strings.ReplaceAll(peer, "987654321", "18446744073709551615")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, calls = test.output, 0
			err := native.VerifyNativeRevokedPairQEMU(context.Background(), pair)
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativeSessionPairChangedQEMU) || calls != 1 {
				t.Fatalf("uncertain or non-original peer became revocation: calls=%d err=%v", calls, err)
			}
		})
	}
	fixture, commandErr, calls = peer, errors.New("private command failure"), 0
	if err := native.VerifyNativeRevokedPairQEMU(context.Background(), pair); !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatal("failed command with valid-looking output became revocation", err, calls)
	}
	commandErr, calls = nil, 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelReply = cancel
	if err := native.VerifyNativeRevokedPairQEMU(ctx, pair); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatal("late nil after cancellation became revocation", err, calls)
	}
}

func TestNativeRevokedPairRefusesInvalidAuthorityWithoutDispatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	calls := 0
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
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
	calls = 0
	var absent *NativeBackendQEMU
	for _, operation := range []func() error{
		func() error { return absent.VerifyNativeRevokedPairQEMU(context.Background(), pair) },
		func() error { return native.VerifyNativeRevokedPairQEMU(nil, pair) },
		func() error { return native.VerifyNativeRevokedPairQEMU(context.Background(), NativeSessionPairQEMU{}) },
		func() error {
			return (&NativeBackendQEMU{inner: backend}).VerifyNativeRevokedPairQEMU(context.Background(), pair)
		},
	} {
		if err := operation(); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid/foreign authority admitted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := native.VerifyNativeRevokedPairQEMU(ctx, pair); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancellation lost", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if err := native.VerifyNativeRevokedPairQEMU(expired, pair); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired observation admitted", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := native.VerifyNativeRevokedPairQEMU(context.Background(), pair); !errors.Is(err, ErrInvalid) {
		t.Fatal("closed inner adapter admitted", err)
	}
	if calls != 0 {
		t.Fatal("invalid/canceled/closed observation dispatched a status worker", calls)
	}
}

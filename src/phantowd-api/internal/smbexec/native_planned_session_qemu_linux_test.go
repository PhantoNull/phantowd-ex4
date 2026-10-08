//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNativePlannedSessionRequiresOriginalAuthorizedGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, args []string, _ *os.File, input []byte, capture bool) ([]byte, error) {
		if executable != smbstatusPath || len(args) != 3 || args[0] != "-j" || args[1] != "-s" || args[2] != configArgument || len(input) != 0 || !capture {
			t.Fatal("planned session observation escaped fixed read-only status")
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedSessionQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := native.VerifyPlannedSessionQEMU(context.Background(), original); err != nil {
		t.Fatal("original authorized session refused:", err)
	}
	fixture = strings.ReplaceAll(fixture, "987654321", "987654322")
	if err := native.VerifyPlannedSessionQEMU(context.Background(), original); !errors.Is(err, ErrNativePlannedSessionChangedQEMU) {
		t.Fatal("replacement generation became original continuity:", err)
	}
}

func TestNativePlannedSessionRefusesPartialForeignAndFailedInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	original := strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	fixture, commandErr := original, error(nil)
	dispatched := false
	var cancelOnReply context.CancelFunc
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		dispatched = true
		if cancelOnReply != nil {
			cancelOnReply()
		}
		return []byte(fixture), commandErr
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	witness, err := native.ObservePlannedSessionQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, fixtureValue := range []string{
		strings.ReplaceAll(original, "qpsecond", "qpmanaged"),
		strings.ReplaceAll(original, "qpsecond", "foreign"),
		strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true))),
		`{"sessions":{}}`, `{"sessions":null}`, `{"sessions":{},"sessions":{}}`,
		strings.ReplaceAll(original, "987654321", "18446744073709551615"),
	} {
		fixture = fixtureValue
		if observed, err := native.ObservePlannedSessionQEMU(context.Background()); observed != (NativePlannedSessionQEMU{}) || err == nil {
			t.Fatal("ungranted, foreign or incomplete session became a witness:", err)
		}
	}
	fixture = original
	commandErr = errors.New("private status failure")
	if err := native.VerifyPlannedSessionQEMU(context.Background(), witness); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedSessionChangedQEMU) {
		t.Fatal("status failure was interpreted as session change:", err)
	}
	commandErr = nil
	fixture = `{"sessions":null}`
	if err := native.VerifyPlannedSessionQEMU(context.Background(), witness); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedSessionChangedQEMU) {
		t.Fatal("parser failure was interpreted as session change:", err)
	}
	fixture = original
	dispatched = false
	var absent *NativeBackendQEMU
	for _, operation := range []func() error{
		func() error { _, err := absent.ObservePlannedSessionQEMU(context.Background()); return err },
		func() error { return native.VerifyPlannedSessionQEMU(context.Background(), NativePlannedSessionQEMU{}) },
		func() error {
			return (&NativeBackendQEMU{inner: backend}).VerifyPlannedSessionQEMU(context.Background(), witness)
		},
		func() error { return native.VerifyPlannedSessionQEMU(nil, witness) },
	} {
		if err := operation(); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid witness admitted:", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := native.VerifyPlannedSessionQEMU(ctx, witness); !errors.Is(err, context.Canceled) || dispatched {
		t.Fatal("pre-canceled observation dispatched or lost cancellation:", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	cancelOnReply = cancel
	if err := native.VerifyPlannedSessionQEMU(ctx, witness); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("late status success became session continuity:", err)
	}
	if _, err := json.Marshal(witness); err == nil || json.Unmarshal([]byte(`{}`), &witness) == nil {
		t.Fatal("private witness crossed serialization boundary")
	}
}

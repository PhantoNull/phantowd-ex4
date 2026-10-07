//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// The command runner substitutes only the external Samba boundary. Both
// adapters execute their real Disable path, including complete status parsing.
func TestDisableKeepsFixedAdapterBudgetAndParentDeadline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	for _, test := range []struct {
		name    string
		native  bool
		parent  time.Duration
		control time.Duration
		status  time.Duration
	}{
		{"ordinary", false, 0, 5 * time.Second, 2 * time.Second},
		{"native-complete-admission", true, 0, 4 * time.Second, 4 * time.Second},
		{"native-parent-shorter", true, 2 * time.Second, 2 * time.Second, 2 * time.Second},
		{"ordinary-parent-shorter", false, 2 * time.Second, 2 * time.Second, 2 * time.Second},
		{"native-parent-longer", true, 30 * time.Second, 4 * time.Second, 4 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			statusCalls, controlCalls := 0, 0
			backend, err := testBackend(t, secureConfig(t), runnerFunc(func(ctx context.Context, executable string, args []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
				switch executable {
				case smbpasswdPath:
					return nil, nil
				case smbstatusPath:
					deadline, ok := ctx.Deadline()
					remaining := time.Until(deadline)
					if !ok || remaining <= test.status-time.Second || remaining > test.status {
						t.Fatalf("fixed bounded status budget = %v; want at most %v with parent respected", remaining, test.status)
					}
					statusCalls++
					return []byte(strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(statusCalls == 1)))), nil
				case smbcontrolPath:
					controlCalls++
					deadline, ok := ctx.Deadline()
					remaining := time.Until(deadline)
					if !ok || remaining <= test.control-time.Second || remaining > test.control {
						t.Fatalf("fixed bounded control budget = %v; want at most %v with parent respected", remaining, test.control)
					}
					if len(args) != 5 || args[4] != "qpmanaged" {
						t.Fatal("revocation escaped target-only control")
					}
					return nil, nil
				default:
					t.Fatalf("unexpected external command %q", executable)
					return nil, ErrUnavailable
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if test.parent != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.parent)
				defer cancel()
			}
			account := serviceaccounts.Account{ID: "managed", Name: "qpmanaged", UID: 2000, GID: 2000, State: serviceaccounts.Disabled}
			if test.native {
				err = (&NativeBackendQEMU{inner: backend}).Disable(ctx, account)
			} else {
				err = backend.Disable(ctx, account)
			}
			if err != nil || controlCalls != 1 || statusCalls != 3 {
				t.Fatalf("target-only logoff and two complete absent inventories: error=%v control=%d status=%d", err, controlCalls, statusCalls)
			}
		})
	}
}

func TestNativeSessionWitnessRequiresSameBackendAndSamePeerGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, _ []string, _ *os.File, _ []byte, capture bool) ([]byte, error) {
		if executable != smbstatusPath || !capture {
			t.Fatal("witness escaped read-only status boundary")
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
	if _, err := json.Marshal(pair); err == nil {
		t.Fatal("private witness serialized")
	}
	var decoded NativeSessionPairQEMU
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil {
		t.Fatal("private witness deserialized")
	}
	if err := native.VerifyNativePeerSessionQEMU(context.Background(), NativeSessionPairQEMU{}); err == nil {
		t.Fatal("empty witness admitted")
	}
	if err := (&NativeBackendQEMU{inner: backend}).VerifyNativePeerSessionQEMU(context.Background(), pair); err == nil {
		t.Fatal("foreign backend witness admitted")
	}
	peer := strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond")
	for _, invalid := range []string{
		fixture,
		`{"sessions":{}}`,
		`{"sessions":null}`,
		strings.ReplaceAll(peer, "987654321", "987654322"),
		strings.ReplaceAll(peer, "1000000000002", "1000000000003"),
		strings.ReplaceAll(peer, "1002", "1003"),
		strings.ReplaceAll(peer, "qpsecond", "qpmanaged"),
		strings.ReplaceAll(peer, "987654321", "18446744073709551615"),
	} {
		fixture = invalid
		if err := native.VerifyNativePeerSessionQEMU(context.Background(), pair); err == nil {
			t.Fatal("absence, replacement or malformed inventory substituted for peer continuity")
		}
	}
	fixture = peer
	if err := native.VerifyNativePeerSessionQEMU(context.Background(), pair); err != nil {
		t.Fatal("same qualified peer session refused:", err)
	}
}

func TestNativeSessionPairRejectsIncompleteOrAmbiguousCoverage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	valid := strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(true)))
	var fixture string
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	for _, invalid := range []string{
		`{}`,
		`{"sessions":{}}`,
		strings.ReplaceAll(string(testSMBStatusJSON(false)), "bob", "qpsecond"),
		strings.ReplaceAll(valid, "qpmanaged", "qpsecond"),
		strings.ReplaceAll(valid, "qpmanaged", "foreign"),
		strings.ReplaceAll(strings.ReplaceAll(valid, "1001", "1002"), "123456789", "987654321"),
		strings.ReplaceAll(valid, "123456789", "0"),
		`{"sessions":{},"sessions":{}}`,
	} {
		fixture = invalid
		pair, err := native.ObserveNativeSessionPairQEMU(context.Background())
		if err == nil || pair.backend != nil {
			t.Fatal("partial/ambiguous inventory returned an authorized pair witness")
		}
	}
}

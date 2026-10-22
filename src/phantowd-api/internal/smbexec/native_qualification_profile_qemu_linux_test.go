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
	"testing/synctest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// The real backend/observer selects deadlines; only the external command runner
// is substituted. This is not a healthy native runtime or process admission.
func TestNativeQualificationAndLegacyAdaptersRetainFixedBudgets(t *testing.T) {
	for _, qualified := range []bool{false, true} {
		for _, shorter := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				config, err := os.CreateTemp(t.TempDir(), "fixture-config-")
				if err != nil {
					t.Fatal(err)
				}
				defer config.Close()
				want := 4 * time.Second
				if qualified {
					want = 8 * time.Second
				}
				parent := context.Background()
				if shorter {
					var cancel context.CancelFunc
					parent, cancel = context.WithTimeout(parent, 2*time.Second)
					defer cancel()
					want = 2 * time.Second
				}
				statusCalls, controls := 0, 0
				backend := &Backend{config: config, runner: runnerFunc(func(ctx context.Context, executable string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
					if executable == smbpasswdPath {
						return nil, nil
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > want || time.Until(deadline) <= want-time.Second {
						t.Fatalf("adapter deadline escaped fixed/parent budget: qualified=%t shorter=%t remaining=%v", qualified, shorter, time.Until(deadline))
					}
					switch executable {
					case smbstatusPath:
						statusCalls++
						return []byte(strings.NewReplacer("alice", "qpmanaged", "bob", "qpsecond").Replace(string(testSMBStatusJSON(statusCalls == 1)))), nil
					case smbcontrolPath:
						controls++
						return nil, nil
					default:
						t.Fatalf("unexpected fixture command %q", executable)
						return nil, ErrInvalid
					}
				})}
				native := &NativeBackendQEMU{inner: backend, qualification: qualified}
				account := serviceaccounts.Account{ID: "managed", Name: "qpmanaged", UID: 2000, GID: 2000, State: serviceaccounts.Disabled}
				if err := native.Disable(parent, account); err != nil || statusCalls != 3 || controls != 1 || native.qualification != qualified {
					t.Fatal("profile changed, target-only control retried or complete inventories lost", err, statusCalls, controls)
				}
				statusCalls = 0
				if _, err := native.readNativeSessionsQEMU(parent); err != nil || statusCalls != 1 {
					t.Fatal("pair observer lost retained fixed profile", err, statusCalls)
				}
			})
		}
	}
}

func TestNativeConstructorsRejectBeforeConfigOrProcessEffects(t *testing.T) {
	for _, constructor := range []func(context.Context, *runtimebundle.NativeSambaRuntimeQEMU) (*NativeBackendQEMU, error){NewNativeBackendQEMU, NewNativeQualificationBackendQEMU} {
		if backend, err := constructor(nil, nil); backend != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("nil constructor inputs accepted", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if backend, err := constructor(ctx, &runtimebundle.NativeSambaRuntimeQEMU{}); backend != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled construction reached configuration or process admission", err)
		}
	}
}

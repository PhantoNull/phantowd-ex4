//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func TestRevocationProfilesAreFixedAndCommandLimitsUnchanged(t *testing.T) {
	ordinary, ok := commandRevocationProfile.limits()
	if !ok || ordinary != (revocationLimits{5 * time.Second, 2 * time.Second, 5 * time.Second}) {
		t.Fatal("ordinary command limits changed", ordinary, ok)
	}
	native, ok := nativeQEMURevocationProfile.limits()
	if !ok || native != (revocationLimits{20 * time.Second, 4 * time.Second, 4 * time.Second}) {
		t.Fatal("native fixture profile is not fixed", native, ok)
	}
	phaseBound := time.Duration(1+stableAbsentSessionInventories)*native.status + native.control + time.Duration(stableAbsentSessionInventories)*sessionPollInterval
	if native.total <= phaseBound {
		t.Fatal("native total cannot cover complete bounded worker sequence", native, phaseBound)
	}
}

func TestRevocationRefusesUnknownProfileBeforeAnyCommand(t *testing.T) {
	config, err := os.CreateTemp(t.TempDir(), "configuration-")
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	calls := 0
	backend := &Backend{config: config, runner: runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	})}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	for _, profile := range []revocationProfile{0, 3, 255} {
		if limits, ok := profile.limits(); ok || limits != (revocationLimits{}) {
			t.Fatal("unknown profile returned partial limits", profile, limits, ok)
		}
		if err := backend.disableWithProfile(context.Background(), account, profile); err != ErrInvalid || calls != 0 {
			t.Fatal("unknown profile dispatched a command", profile, err, calls)
		}
	}
}

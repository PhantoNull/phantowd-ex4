//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"
)

// Fixed fixture workloads; no authority, backend, retry or product API hook.
// The SAME Owner, runtime and session witness cross the caller's two closures.
// Live continuity/revocation keeps 45s; fresh authentication has a separate 15s.
// This explicitly changes fixture allowance 45->60, not worker/product/guest
// limits or throughput. A failed/late phase never renews a timer or retries.
func runNativeLivePhasesQEMU(parent context.Context, live, authenticate func(context.Context) error) error {
	if parent == nil || live == nil || authenticate == nil {
		return errors.New("native live fixture requires both phases and parent")
	}
	budgets := [...]time.Duration{nativeLiveLimitQEMU, nativeFreshLoginLimitQEMU}
	for index, phase := range []func(context.Context) error{live, authenticate} {
		if err := parent.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(parent, budgets[index])
		if err := nativeLivePhaseErrorQEMU(ctx); err != nil {
			cancel()
			return err
		}
		err := errors.Join(phase(ctx), nativeLivePhaseErrorQEMU(ctx), parent.Err())
		cancel()
		if err != nil {
			return err
		}
	}
	return parent.Err()
}

// A timer's cancellation goroutine may not have run at the exact deadline.
// Check the original monotonic deadline too: late nil is never a handoff.
func nativeLivePhaseErrorQEMU(ctx context.Context) error {
	err := ctx.Err()
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errors.Join(err, errors.New("native live fixture requires a deadline"))
	}
	if !time.Now().Before(deadline) {
		return errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

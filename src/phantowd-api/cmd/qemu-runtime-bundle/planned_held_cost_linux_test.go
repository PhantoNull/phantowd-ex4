//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestPlannedHeldCostsDescribeCumulativeBoundariesWithoutCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		clock := startPlannedHeldCostQEMU(ctx)
		for _, elapsed := range []time.Duration{3 * time.Second, 5 * time.Second, 4 * time.Second, time.Second} {
			time.Sleep(elapsed)
			clock.mark()
		}
		time.Sleep(2 * time.Second)
		const want = "PHANTOWD_DIAG_HELD_COSTS stage=close steps=4 budget_ms=20000 after_start_ms=3000 after_live_ms=8000 after_supervision_ms=12000 after_stopped_ms=13000 total_ms=15000 failed=false context_done=false deadline_reached=false qualifying=false scope=qemu-only\n"
		if got := clock.row(ctx, nil); got != want {
			t.Fatal("incorrect cumulative held costs", got)
		}
		private := errors.New("private/path/password")
		if got := clock.row(ctx, private); strings.Contains(got, "private") || !strings.Contains(got, "failed=true") {
			t.Fatal("cause leaked or failure changed", got)
		}
	})
}

func TestPlannedHeldCostsRefuseUnknownOrChangedClockAndExposeExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		clock := startPlannedHeldCostQEMU(ctx)
		if clock.row(context.Background(), nil) != "" {
			t.Fatal("unbounded replacement context supplied diagnostic")
		}
		other, cancelOther := context.WithTimeout(ctx, time.Second)
		defer cancelOther()
		if clock.row(other, nil) != "" {
			t.Fatal("changed deadline supplied diagnostic")
		}
		time.Sleep(3 * time.Second)
		clock.mark()
		time.Sleep(18 * time.Second)
		synctest.Wait()
		row := clock.row(ctx, context.DeadlineExceeded)
		if !strings.Contains(row, "stage=live-observation steps=1") || !strings.Contains(row, "total_ms=21000 failed=true context_done=true deadline_reached=true") {
			t.Fatal("expiry or incomplete boundary hidden", row)
		}
		for _, bad := range []plannedHeldCostClockQEMU{
			{}, startPlannedHeldCostQEMU(nil), startPlannedHeldCostQEMU(context.Background()),
			{start: time.Now().Add(time.Second), deadline: time.Now().Add(2 * time.Second)},
			{start: time.Now().Add(-181 * time.Second), deadline: time.Now().Add(time.Second)},
			{start: time.Now(), deadline: time.Now().Add(time.Second), steps: 5},
		} {
			if bad.row(ctx, nil) != "" {
				t.Fatal("invalid clock emitted a row")
			}
		}
	})
}

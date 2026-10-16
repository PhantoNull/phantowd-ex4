//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestNativePlannedDataCostsMeasureOriginalBudgetAndThreeBoundaries(t *testing.T) {
	for _, available := range []time.Duration{20 * time.Second, 7 * time.Second} {
		for steps, stage := range []string{"before-runtime", "runtime", "after-runtime"} {
			t.Run(stage+available.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					parent, cancelParent := context.WithTimeout(context.Background(), available)
					defer cancelParent()
					ctx, cancel := context.WithTimeout(parent, 20*time.Second)
					defer cancel()
					clock := startNativePlannedDataCostQEMU(ctx)
					if steps > 0 {
						time.Sleep(time.Second)
						clock.mark()
					}
					if steps > 1 {
						time.Sleep(4 * time.Second)
						clock.mark()
					}
					time.Sleep(available)
					synctest.Wait()
					private := errors.New("private-path/credential\nFAKE_READY")
					original := plannedDataStageFailureQEMU(stage, plannedFailureQEMU(ctx, "verify-owners", private))
					err := clock.annotate(original)
					want := NativePlannedDataCostObservationQEMU{Present: true, Steps: uint8(steps), BudgetMS: available.Milliseconds(), TotalMS: available.Milliseconds()}
					if steps > 0 {
						want.BeforeMS, want.TotalMS = 1000, want.TotalMS+1000
					}
					if steps > 1 {
						want.ProbeMS, want.TotalMS = 5000, want.TotalMS+4000
					}
					if got := ObserveNativePlannedDataCostQEMU(err); got != want || !errors.Is(err, original) || !errors.Is(err, private) || errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("clock changed original cause/budget or cumulative costs", got, want)
					}
					if strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
						t.Fatal("diagnostic leaked cause")
					}
					time.Sleep(time.Minute)
					if ObserveNativePlannedDataCostQEMU(err) != want || clock.annotate(err) != err {
						t.Fatal("cleanup or outer annotation replaced original snapshot")
					}
				})
			})
		}
	}
}

func TestNativePlannedDataCostsRefuseAbsentForgedAndOutOfOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cause := plannedDataStageFailureQEMU("after-runtime", errors.New("private"))
		for _, clock := range []nativePlannedDataCostClockQEMU{
			{}, startNativePlannedDataCostQEMU(nil), startNativePlannedDataCostQEMU(context.Background()), startNativePlannedDataCostQEMU(ctx),
		} {
			if clock.annotate(cause) != cause || clock.annotate(nil) != nil {
				t.Fatal("missing/unreached clock produced telemetry")
			}
		}
		clock := startNativePlannedDataCostQEMU(ctx)
		clock.mark()
		clock.mark()
		clock.mark()
		if clock.annotate(cause) != cause {
			t.Fatal("out-of-order clock admitted")
		}
		valid := NativePlannedDataCostObservationQEMU{Present: true, Steps: 2, BudgetMS: 20000, BeforeMS: 1000, ProbeMS: 19000, TotalMS: 20001}
		for _, bad := range []NativePlannedDataCostObservationQEMU{
			{}, {Present: true, Steps: 3}, {Present: true, Steps: 0, BeforeMS: 1},
			{Present: true, Steps: 1, ProbeMS: 1}, {Present: true, Steps: 2, BeforeMS: 2, ProbeMS: 1, TotalMS: 3},
			{Present: true, BudgetMS: -1}, {Present: true, BudgetMS: 180001},
			{Present: true, TotalMS: 180001}, {Present: true, Steps: 2, ProbeMS: 2, TotalMS: 1},
		} {
			if validNativePlannedDataCostQEMU(bad) || ObserveNativePlannedDataCostQEMU(&nativePlannedDataCostFailureQEMU{cause: cause, cost: bad}).Present {
				t.Fatal("invalid clock admitted")
			}
		}
		for _, good := range []NativePlannedDataCostObservationQEMU{
			{Present: true}, {Present: true, Steps: 1, BeforeMS: 100, TotalMS: 100}, valid,
			{Present: true, Steps: 2, BudgetMS: 180000, BeforeMS: 180000, ProbeMS: 180000, TotalMS: 180000},
		} {
			if !validNativePlannedDataCostQEMU(good) {
				t.Fatal("valid independent numeric boundary refused")
			}
		}
		for _, err := range []error{nil, cause, (*nativePlannedDataCostFailureQEMU)(nil), &nativePlannedDataCostFailureQEMU{cost: valid}, &nativePlannedDataCostFailureQEMU{cause: errors.New("private"), cost: valid}} {
			if ObserveNativePlannedDataCostQEMU(err).Present {
				t.Fatal("unqualified cause gained timing")
			}
		}
	})
}

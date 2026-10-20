//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestPlannedDataCostPartitionsElapsedWithoutChangingCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clock := plannedDataCostClockQEMU{start: time.Now()}
		time.Sleep(2 * time.Second)
		clock.mark(false)
		time.Sleep(3 * time.Second)
		clock.mark(true)
		time.Sleep(time.Second)
		cost := clock.finish()
		cause := errors.Join(ErrReviewRequired, context.DeadlineExceeded, errors.New("private/path/secret"))
		err := cost.AnnotateFailureQEMU(cause)
		want := PlannedDataCostQEMU{Present: true, ChecksNS: int64(2 * time.Second), ClientsNS: int64(3 * time.Second), RemainderNS: int64(time.Second), Checks: 1, Clients: 1}
		if got := ObservePlannedDataCostQEMU(err); got != want || !errors.Is(err, cause) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("cost partition changed cause or elapsed accounting", got, want)
		}
		if strings.Contains(err.Error(), "private") || cost.AnnotateFailureQEMU(nil) != nil {
			t.Fatal("diagnostic leaked underlying data or changed success")
		}
		time.Sleep(time.Minute)
		if ObservePlannedDataCostQEMU(err) != want || cost.AnnotateFailureQEMU(err) != err {
			t.Fatal("cleanup replaced original cost snapshot")
		}
	})
}

func TestPlannedDataCostRefusesInvalidAndUnadmittedRuntime(t *testing.T) {
	private := errors.New("private")
	for _, c := range []PlannedDataCostQEMU{
		{}, {Present: true, Checks: 14}, {Present: true, Clients: 7},
		{Present: true, ChecksNS: 1}, {Present: true, ClientsNS: 1},
		{Present: true, Checks: 1, ChecksNS: -1}, {Present: true, Checks: 1, ChecksNS: 180_000_000_001},
		{Present: true, Checks: 1, Clients: 1, ChecksNS: 100_000_000_000, ClientsNS: 100_000_000_000},
	} {
		if c.AnnotateFailureQEMU(private) != private {
			t.Fatal("invalid cost changed error", c)
		}
	}
	var absent *NativeSambaRuntimeQEMU
	if cost, err := absent.ProbePlannedDataAccessMeasuredQEMU(context.Background()); cost.Present || !errors.Is(err, ErrInvalid) {
		t.Fatal("unadmitted runtime supplied costs", cost, err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cost, err := r.ProbePlannedDataAccessMeasuredQEMU(ctx); cost.Present || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled runtime proceeded", cost, err)
	}
	for _, clock := range []plannedDataCostClockQEMU{{}, {start: time.Now().Add(time.Hour)}, {start: time.Now().Add(-181 * time.Second)}} {
		clock.mark(false)
		if clock.finish().Present {
			t.Fatal("invalid clock invented cost")
		}
	}
}

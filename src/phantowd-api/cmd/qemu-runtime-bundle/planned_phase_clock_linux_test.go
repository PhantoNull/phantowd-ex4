//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

func TestPlannedPhaseClockKeepsExistingCapsAndOriginalParent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if plannedStartupLimitQEMU != 40*time.Second || plannedDataLimitQEMU != 20*time.Second || plannedSupervisionLimitQEMU != 20*time.Second || plannedFaultLimitQEMU != 90*time.Second {
			t.Fatal("pending budget choice silently changed existing caps")
		}
		type key struct{}
		parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "original"), 35*time.Second)
		defer cancel()
		clock, err := newPlannedPhaseClockQEMU(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer clock.Close()
		deadline, _ := clock.ctx.Deadline()
		time.Sleep(20 * time.Second)
		old := clock.ctx
		if err := clock.Advance(plannedDataQEMU); err != nil {
			t.Fatal(err)
		}
		next, _ := clock.ctx.Deadline()
		if next != deadline || time.Until(next) != 15*time.Second || clock.ctx.Value(key{}) != "original" || old.Err() != context.Canceled {
			t.Fatal("data phase renewed parent or inherited canceled startup")
		}
		time.Sleep(14 * time.Second)
		if err := clock.Advance(plannedSupervisionQEMU); err != nil {
			t.Fatal(err)
		}
		next, _ = clock.ctx.Deadline()
		if next != deadline || time.Until(next) != time.Second || clock.ctx.Value(key{}) != "original" {
			t.Fatal("supervision escaped original parent")
		}
		time.Sleep(time.Second)
		if !errors.Is(clock.Check(), context.DeadlineExceeded) {
			t.Fatal("expired parent could qualify proof")
		}
	})
}

func TestPlannedPhaseClockExpiredOrCanceledWorkCannotAdvance(t *testing.T) {
	for _, stage := range []plannedPhaseQEMU{plannedStartupQEMU, plannedDataQEMU, plannedSupervisionQEMU} {
		synctest.Test(t, func(t *testing.T) {
			clock, err := newPlannedPhaseClockQEMU(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer clock.Close()
			for next := plannedDataQEMU; next <= stage; next++ {
				if err := clock.Advance(next); err != nil {
					t.Fatal(err)
				}
			}
			deadline, _ := clock.ctx.Deadline()
			time.Sleep(time.Until(deadline))
			old := clock.ctx
			if !errors.Is(clock.Check(), context.DeadlineExceeded) || !errors.Is(clock.Advance(stage+1), context.DeadlineExceeded) || clock.ctx != old {
				t.Fatal("late completion received a fresh phase timer")
			}
		})
	}
	parent, cancel := context.WithCancel(context.Background())
	clock, err := newPlannedPhaseClockQEMU(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	cancel()
	if !errors.Is(clock.Advance(plannedDataQEMU), context.Canceled) || !errors.Is(clock.Check(), context.Canceled) {
		t.Fatal("parent cancellation detached at transition")
	}
}

type plannedLateDeadlineContextQEMU struct {
	context.Context
	end time.Time
}

func (c plannedLateDeadlineContextQEMU) Deadline() (time.Time, bool) { return c.end, true }

func TestPlannedPhaseClockRejectsLateNilBeforeTimerNotification(t *testing.T) {
	clock, err := newPlannedPhaseClockQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	clock.cancel()
	clock.ctx = plannedLateDeadlineContextQEMU{Context: context.Background(), end: time.Now().Add(-time.Nanosecond)}
	if clock.ctx.Err() != nil || !errors.Is(clock.Advance(plannedDataQEMU), context.DeadlineExceeded) {
		t.Fatal("nil context error hid the original monotonic deadline")
	}
}

func TestPlannedPhaseClockInvalidTransitionsCopiesAndDisposal(t *testing.T) {
	clock, err := newPlannedPhaseClockQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	copy := *clock
	copy.Close()
	if !errors.Is(copy.Check(), errPlannedPhaseQEMU) || clock.Check() != nil {
		t.Fatal("value copy forked/canceled original clock")
	}
	old := clock.ctx
	if !errors.Is(clock.Advance(plannedSupervisionQEMU), errPlannedPhaseQEMU) || clock.ctx != old {
		t.Fatal("out-of-order transition changed clock")
	}
	if err := clock.Advance(plannedDataQEMU); err != nil {
		t.Fatal(err)
	}
	old = clock.ctx
	if !errors.Is(clock.Advance(plannedDataQEMU), errPlannedPhaseQEMU) || clock.ctx != old {
		t.Fatal("repeated data phase renewed clock")
	}
	clock.Close()
	if old.Err() != context.Canceled || !errors.Is(clock.Check(), errPlannedPhaseQEMU) {
		t.Fatal("disposal left live timer or qualification")
	}
	for _, bad := range []*plannedPhaseClockQEMU{nil, {}} {
		bad.Close()
		if !errors.Is(bad.Check(), errPlannedPhaseQEMU) {
			t.Fatal("unconstructed clock admitted")
		}
	}
}

func TestPlannedFixtureCanceledParentRefusesBeforeAnyInputsOrSubprocess(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, parent} {
		if clock, err := newPlannedPhaseClockQEMU(ctx); clock != nil || err == nil {
			t.Fatal("invalid parent created phase clock")
		}
		// Real guarded entry points, with no backend/plan/path fixture. They must
		// reject before touching the hardcoded guest inputs or spawning a child.
		if err := nativePlannedServiceFixtureQEMU(ctx, nil, fileserviceplan.SambaEnrollmentLookup{}, "", nil, ""); err == nil {
			t.Fatal("invalid parent reached real fixture inputs")
		}
		if err := nativePlannedFaultSubprocessQEMU(ctx, "source"); err == nil {
			t.Fatal("invalid parent reached real fixed subprocess")
		}
	}
	if !errors.Is(nativePlannedServiceFixtureQEMU(parent, nil, fileserviceplan.SambaEnrollmentLookup{}, "", nil, ""), context.Canceled) || !errors.Is(nativePlannedFaultSubprocessQEMU(parent, "source"), context.Canceled) {
		t.Fatal("real canceled fixture admission lost parent cause")
	}
}

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
)

func TestNativeCampaignClockPolicy(t *testing.T) {
	sum := nativePreparationLimitQEMU + nativeEnrollmentLimitQEMU + nativeBackendLimitQEMU + nativeDaemonLimitQEMU + nativeIdleLimitQEMU + nativeClientsLimitQEMU + nativeLiveLimitQEMU + nativeFreshLoginLimitQEMU + nativeDataLimitQEMU
	if sum != 255*time.Second || sum > nativeCampaignWorkSecondsQEMU*time.Second || nativeCampaignWorkSecondsQEMU+nativeCampaignSettlementSecondsQEMU+nativeCampaignBootSecondsQEMU != 360 {
		t.Fatal("incoherent native fixture policy")
	}
}

func TestNativeCampaignClockRetainsParentAndOneAbsoluteSettlement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type key struct{}
		parent, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "original"))
		defer cancel()
		clock, err := newNativeCampaignClockQEMU(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer clock.Close()
		workEnd, _ := clock.work.Deadline()
		settleEnd, _ := clock.settlement.Deadline()
		if time.Until(workEnd) != 300*time.Second || settleEnd.Sub(workEnd) != 30*time.Second || clock.work.Value(key{}) != "original" || clock.settlement.Value(key{}) != "original" {
			t.Fatal("clock lost original parent or fixed reserves")
		}
		time.Sleep(10 * time.Second)
		cancel()
		if !errors.Is(clock.work.Err(), context.Canceled) || clock.settlement.Err() != nil {
			t.Fatal("work cancellation canceled required settlement")
		}
		time.Sleep(300 * time.Second)
		end, _ := clock.settlement.Deadline()
		if end != settleEnd || clock.settlement.Err() != nil || time.Until(end) != 20*time.Second {
			t.Fatal("settlement was renewed or consumed by work cancellation")
		}
		time.Sleep(20 * time.Second)
		if !errors.Is(nativeLivePhaseErrorQEMU(clock.settlement), context.DeadlineExceeded) {
			t.Fatal("late nil could qualify settlement")
		}
	})
}

func TestNativeCampaignClockShorterParentNeverRenews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		clock, err := newNativeCampaignClockQEMU(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer clock.Close()
		time.Sleep(40 * time.Second)
		phase, stop := context.WithTimeout(clock.work, nativeDaemonLimitQEMU)
		defer stop()
		end, _ := phase.Deadline()
		if time.Until(end) != 10*time.Second {
			t.Fatal("late phase detached from shorter original work clock")
		}
		time.Sleep(10 * time.Second)
		if !errors.Is(nativeLivePhaseErrorQEMU(phase), context.DeadlineExceeded) || clock.settlement.Err() != nil {
			t.Fatal("deadline qualification or settlement reserve lost")
		}
		end, _ = clock.settlement.Deadline()
		if time.Until(end) != 30*time.Second {
			t.Fatal("shorter parent was replaced for settlement")
		}
		clock.Close()
		if clock.settlement.Err() != context.Canceled {
			t.Fatal("explicit disposal leaves settlement timer alive")
		}
	})
}

func TestNativeCampaignClockRejectsInvalidParent(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	for _, parent := range []context.Context{nil, parent} {
		if clock, err := newNativeCampaignClockQEMU(parent); clock != nil || err == nil {
			t.Fatal("invalid parent allocated a new campaign")
		}
	}
}

func TestNativeCampaignClockActuallyBoundsBothLivePhases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clock, err := newNativeCampaignClockQEMU(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer clock.Close()
		time.Sleep(260 * time.Second)
		calls := [2]int{}
		err = runNativeLivePhasesQEMU(clock.work, func(ctx context.Context) error {
			calls[0]++
			end, _ := ctx.Deadline()
			if time.Until(end) != 40*time.Second {
				t.Fatal("live work renewed the original total budget")
			}
			time.Sleep(35 * time.Second)
			return nil
		}, func(ctx context.Context) error {
			calls[1]++
			end, _ := ctx.Deadline()
			if time.Until(end) != 5*time.Second {
				t.Fatal("fresh authentication renewed remaining total budget")
			}
			time.Sleep(6 * time.Second)
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != [2]int{1, 1} || clock.settlement.Err() != nil {
			t.Fatal("late work qualified, retried, or canceled settlement", calls, err)
		}
	})
}

func TestNativeCampaignClockSettlementRejectsLateNilAndRetainsCause(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			clock, err := newNativeCampaignClockQEMU(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer clock.Close()
			time.Sleep(2 * time.Second)
			cause := errors.New("uncertain stop")
			calls := 0
			err = clock.Settle(func(ctx context.Context) error {
				calls++
				if ctx.Err() != nil {
					t.Fatal("expired work context was passed to settlement")
				}
				time.Sleep(30 * time.Second)
				if uncertain {
					return cause
				}
				return nil
			})
			if !errors.Is(err, context.DeadlineExceeded) || (uncertain && !errors.Is(err, cause)) || calls != 1 {
				t.Fatal("late settlement qualified or erased uncertainty", err)
			}
			if err := clock.Settle(func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
				t.Fatal("expired settlement renewed or invoked an operation")
			}
		})
	}
}

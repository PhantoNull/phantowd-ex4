//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"time"
)

// Diagnostic snapshots are taken inside the runtime, BEFORE the containing
// coordinator quarantines/stops processes. No clock/context/authority escapes.
type nativeDataClockQEMU struct {
	start, deadline time.Time
}

type NativeDataClockObservationQEMU struct {
	Present, ContextDone, DeadlineReached            bool
	ElapsedMS, EnteredRemainingMS, FailedRemainingMS int64
}

type nativeDataClockErrorQEMU struct {
	cause error
	clock NativeDataClockObservationQEMU
}

func (*nativeDataClockErrorQEMU) Error() string   { return "native data timed refusal" }
func (e *nativeDataClockErrorQEMU) Unwrap() error { return e.cause }

func startNativeDataClockQEMU(ctx context.Context) nativeDataClockQEMU {
	if ctx == nil {
		return nativeDataClockQEMU{}
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nativeDataClockQEMU{}
	}
	return nativeDataClockQEMU{start: time.Now(), deadline: deadline}
}

func nativeDataRemainingMSQEMU(deadline, now time.Time) int64 {
	if !now.Before(deadline) {
		return 0
	}
	return deadline.Sub(now).Milliseconds()
}

func (c nativeDataClockQEMU) annotate(ctx context.Context, err error) error {
	if err == nil || ctx == nil || c.start.IsZero() || c.deadline.IsZero() ||
		!ObserveNativeDataFailureQEMU(err).Present || ObserveNativeDataClockQEMU(err).Present {
		return err
	}
	now := time.Now()
	if now.Before(c.start) {
		return err
	}
	clock := NativeDataClockObservationQEMU{
		Present: true, ContextDone: ctx.Err() != nil, DeadlineReached: !now.Before(c.deadline),
		ElapsedMS:          now.Sub(c.start).Milliseconds(),
		EnteredRemainingMS: nativeDataRemainingMSQEMU(c.deadline, c.start),
		FailedRemainingMS:  nativeDataRemainingMSQEMU(c.deadline, now),
	}
	if !validNativeDataClockQEMU(clock) {
		return err
	}
	return &nativeDataClockErrorQEMU{cause: err, clock: clock}
}

func validNativeDataClockQEMU(c NativeDataClockObservationQEMU) bool {
	if !c.Present || c.ElapsedMS < 0 || c.ElapsedMS > 180000 ||
		c.EnteredRemainingMS < 0 || c.EnteredRemainingMS > 180000 ||
		c.FailedRemainingMS < 0 || c.FailedRemainingMS > c.EnteredRemainingMS {
		return false
	}
	return !c.DeadlineReached || (c.FailedRemainingMS == 0 && c.ElapsedMS >= c.EnteredRemainingMS)
}

// A bounded immutable timing observation, not a completion/health statement.
// Missing clocks stay missing; original typed causes/classification survive.
func ObserveNativeDataClockQEMU(err error) NativeDataClockObservationQEMU {
	var timed *nativeDataClockErrorQEMU
	if err == nil || !errors.As(err, &timed) || timed == nil || timed.cause == nil ||
		!ObserveNativeDataFailureQEMU(timed.cause).Present || !validNativeDataClockQEMU(timed.clock) {
		return NativeDataClockObservationQEMU{}
	}
	return timed.clock
}

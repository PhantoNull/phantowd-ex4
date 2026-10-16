//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"time"
)

const nativeDataCaptureTimeoutQEMU = 4 * time.Second

type NativeDataCaptureClockObservationQEMU struct {
	NativeDataClockObservationQEMU
	LimitMS int64
}

type nativeDataCaptureClockErrorQEMU struct {
	cause   error
	failure *nativeDataErrorQEMU
	clock   NativeDataClockObservationQEMU
}

func (*nativeDataCaptureClockErrorQEMU) Error() string { return "native data capture timed refusal" }
func (e *nativeDataCaptureClockErrorQEMU) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func validNativeDataCaptureFailureQEMU(e *nativeDataErrorQEMU) bool {
	if e == nil || e.cause == nil || e.stage != nativeWorkerExecutionQEMU {
		return false
	}
	switch e.operation {
	case "rw-write", "rw-read", "ro-read", "ro-write", "escape", "ungranted":
		return true
	default:
		return false
	}
}

// Snapshot immediately after Capture returns, before this caller's Settled and
// Close. Capture itself includes admission, waiting and any internal stop work:
// these numbers are NOT peer-I/O durations or attribution of a timeout cause.
func annotateNativeDataCaptureClockQEMU(ctx context.Context, clock nativeDataClockQEMU, err error) error {
	var failure *nativeDataErrorQEMU
	if err == nil || !errors.As(err, &failure) || !validNativeDataCaptureFailureQEMU(failure) ||
		ObserveNativeDataCaptureClockQEMU(err).Present || ObserveNativeDataClockQEMU(err).Present {
		return err
	}
	// Reuse the bounded monotonic snapshot rules without retaining an aggregate
	// runtime-clock wrapper: the containing runtime keeps its separate clock.
	snapshot := ObserveNativeDataClockQEMU(clock.annotate(ctx, err))
	if !snapshot.Present {
		return err
	}
	return &nativeDataCaptureClockErrorQEMU{cause: err, failure: failure, clock: snapshot}
}

// Private immutable failure observation only. A later joined clock cannot
// displace an earlier data failure; no process, input or authority is exposed.
func ObserveNativeDataCaptureClockQEMU(err error) NativeDataCaptureClockObservationQEMU {
	var timed *nativeDataCaptureClockErrorQEMU
	var first *nativeDataErrorQEMU
	if err == nil || !errors.As(err, &timed) || timed == nil || timed.cause == nil ||
		!errors.As(err, &first) || first != timed.failure || !validNativeDataCaptureFailureQEMU(first) ||
		!validNativeDataClockQEMU(timed.clock) {
		return NativeDataCaptureClockObservationQEMU{}
	}
	return NativeDataCaptureClockObservationQEMU{
		NativeDataClockObservationQEMU: timed.clock, LimitMS: nativeDataCaptureTimeoutQEMU.Milliseconds(),
	}
}

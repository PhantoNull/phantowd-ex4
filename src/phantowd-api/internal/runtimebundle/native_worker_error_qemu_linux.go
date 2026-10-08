//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
)

type nativeWorkerStageQEMU uint8

const (
	nativeWorkerAdmissionQEMU nativeWorkerStageQEMU = iota
	nativeWorkerSettlementQEMU
	nativeWorkerExecutionQEMU
	nativeWorkerPostAdmissionQEMU
	nativeWorkerResultQEMU
)

func nativeWorkerFailureQEMU(stage nativeWorkerStageQEMU, cause error) *nativeWorkerErrorQEMU {
	if cause == nil {
		cause = ErrUnavailable
	}
	return &nativeWorkerErrorQEMU{stage: stage, cause: cause}
}

// Fixed labels disclose no worker stderr, stdin, account name or cause text.
// The private cause stays inspectable via errors.Is without losing review.
type nativeWorkerErrorQEMU struct {
	stage nativeWorkerStageQEMU
	cause error
}

func (e *nativeWorkerErrorQEMU) labels() (string, string) {
	phase := "unknown"
	switch e.stage {
	case nativeWorkerAdmissionQEMU:
		phase = "pre-admission"
	case nativeWorkerSettlementQEMU:
		phase = "settlement"
	case nativeWorkerExecutionQEMU:
		phase = "execution"
	case nativeWorkerPostAdmissionQEMU:
		phase = "post-admission"
	case nativeWorkerResultQEMU:
		phase = "result"
	}
	reason := "other"
	switch {
	case errors.Is(e.cause, context.DeadlineExceeded):
		reason = "deadline"
	case errors.Is(e.cause, context.Canceled):
		reason = "canceled"
	case errors.Is(e.cause, ErrMismatch):
		reason = "mismatch"
	case errors.Is(e.cause, ErrUnavailable):
		reason = "unavailable"
	}
	return phase, reason
}

func (e *nativeWorkerErrorQEMU) Error() string {
	phase, reason := e.labels()
	return fmt.Sprintf("native credential worker phase=%s reason=%s: %s", phase, reason, ErrReviewRequired)
}

func (e *nativeWorkerErrorQEMU) Unwrap() []error {
	return []error{ErrReviewRequired, e.cause}
}

func (r *NativeSambaRuntimeQEMU) nativeWorkerFailureQEMU(stage nativeWorkerStageQEMU, cause error) error {
	err := nativeWorkerFailureQEMU(stage, cause)
	if r.workerFailure == nil {
		r.workerFailure = err
	}
	return err
}

type NativeWorkerFailureObservationQEMU struct {
	Present       bool
	Phase, Reason string
}

// Read-only fixed-label fixture telemetry, not a recovery or admission witness.
// Ordinary adapters may redact backend errors; this preserves only the first
// private runtime failure's classification, never its underlying text/output.
// It remains readable after Close and does not clear review or run any worker.
func (r *NativeSambaRuntimeQEMU) ObserveNativeWorkerFailureQEMU(ctx context.Context) (NativeWorkerFailureObservationQEMU, error) {
	if err := r.enter(ctx); err != nil {
		return NativeWorkerFailureObservationQEMU{}, err
	}
	defer func() { <-r.gate }()
	if r.workerFailure == nil {
		return NativeWorkerFailureObservationQEMU{}, nil
	}
	phase, reason := r.workerFailure.labels()
	return NativeWorkerFailureObservationQEMU{Present: true, Phase: phase, Reason: reason}, nil
}

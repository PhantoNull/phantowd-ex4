//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"time"
)

// Fixture diagnostics only: capture context/deadline flags, never disclose a
// command, account or path. No context or authority is retained in the snapshot.
type NativePlannedFailureObservationQEMU struct {
	Present                                                       bool
	Boundary                                                      string
	ContextPresent, ContextDone, DeadlinePresent, DeadlineReached bool
}

type nativePlannedFailureQEMU struct {
	boundary                                                      string
	cause                                                         error
	contextPresent, contextDone, deadlinePresent, deadlineReached bool
}

func validNativePlannedBoundaryQEMU(boundary string) bool {
	switch boundary {
	case "verify-source-set", "verify-role", "verify-share-pins", "verify-owners", "verify-freshness", "verify-held-session", "verify-held-file", "data-admission", "data-state":
		return true
	case "held-file-admission", "held-file-state", "held-file-retain", "held-file-client", "held-file-observe":
		return true
	default:
		return false
	}
}

func plannedFailureQEMU(ctx context.Context, boundary string, cause error) error {
	if cause == nil || !validNativePlannedBoundaryQEMU(boundary) || ObserveNativePlannedFailureQEMU(cause).Present {
		return cause
	}
	failure := &nativePlannedFailureQEMU{boundary: boundary, cause: cause}
	if ctx != nil {
		failure.contextPresent, failure.contextDone = true, ctx.Err() != nil
		deadline, bounded := ctx.Deadline()
		failure.deadlinePresent = bounded
		failure.deadlineReached = bounded && !time.Now().Before(deadline)
	}
	return failure
}

func (e *nativePlannedFailureQEMU) Error() string {
	boundary := "unavailable"
	if observed := ObserveNativePlannedFailureQEMU(e); observed.Present {
		boundary = observed.Boundary
	}
	return "native planned refusal boundary=" + boundary
}

func (e *nativePlannedFailureQEMU) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Preserve the first fixed boundary and underlying errors.Is/As semantics.
// This observation is not an authority/health/settlement witness.
func ObserveNativePlannedFailureQEMU(err error) NativePlannedFailureObservationQEMU {
	var failure *nativePlannedFailureQEMU
	if !errors.As(err, &failure) || failure == nil || failure.cause == nil || !validNativePlannedBoundaryQEMU(failure.boundary) {
		return NativePlannedFailureObservationQEMU{}
	}
	if (!failure.contextPresent && (failure.contextDone || failure.deadlinePresent || failure.deadlineReached)) || (!failure.deadlinePresent && failure.deadlineReached) {
		return NativePlannedFailureObservationQEMU{}
	}
	return NativePlannedFailureObservationQEMU{Present: true, Boundary: failure.boundary,
		ContextPresent: failure.contextPresent, ContextDone: failure.contextDone,
		DeadlinePresent: failure.deadlinePresent, DeadlineReached: failure.deadlineReached}
}

// A distinct fixed caller stage must not replace the original verification
// boundary/context snapshot. No clock, command or authority is added here.
type nativePlannedDataStageFailureQEMU struct {
	stage string
	cause error
}

func validNativePlannedDataStageQEMU(stage string) bool {
	return stage == "before-runtime" || stage == "runtime" || stage == "after-runtime"
}

func plannedDataStageFailureQEMU(stage string, cause error) error {
	if cause == nil || !validNativePlannedDataStageQEMU(stage) || ObserveNativePlannedDataStageQEMU(cause) != "" {
		return cause
	}
	return &nativePlannedDataStageFailureQEMU{stage: stage, cause: cause}
}

func (e *nativePlannedDataStageFailureQEMU) Error() string {
	stage := ObserveNativePlannedDataStageQEMU(e)
	if stage == "" {
		stage = "unavailable"
	}
	return "native planned data refusal stage=" + stage
}

func (e *nativePlannedDataStageFailureQEMU) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Fixture telemetry only. The first fixed stage survives outer wrapping;
// absent/invalid observations disclose nothing and never prove qualification.
func ObserveNativePlannedDataStageQEMU(err error) string {
	var failure *nativePlannedDataStageFailureQEMU
	if !errors.As(err, &failure) || failure == nil || failure.cause == nil || !validNativePlannedDataStageQEMU(failure.stage) {
		return ""
	}
	return failure.stage
}

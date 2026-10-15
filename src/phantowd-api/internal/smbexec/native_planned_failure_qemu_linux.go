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

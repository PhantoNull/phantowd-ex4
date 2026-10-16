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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNativePlannedFailurePreservesCauseFirstBoundaryAndRedaction(t *testing.T) {
	private := errors.New("private-account/password/path\nFAKE_READY")
	cause := errors.Join(private, runtimebundle.ErrReviewRequired, context.DeadlineExceeded)
	for _, boundary := range []string{"verify-source-set", "verify-role", "verify-share-pins", "verify-owners", "verify-freshness", "verify-held-session", "verify-held-file", "data-admission", "data-state", "held-file-admission", "held-file-state", "held-file-retain", "held-file-client", "held-file-observe"} {
		err := plannedFailureQEMU(context.Background(), boundary, cause)
		if got := ObserveNativePlannedFailureQEMU(err); !got.Present || got.Boundary != boundary {
			t.Fatal("missing fixed failure boundary", got)
		}
		if !errors.Is(err, private) || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, runtimebundle.ErrReviewRequired) || strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatal("annotation changed or disclosed original refusal")
		}
		if plannedFailureQEMU(context.Background(), "data-state", err) != err || plannedFailureQEMU(context.Background(), boundary, nil) != nil {
			t.Fatal("diagnostic replaced original boundary or invented success output")
		}
	}
	for _, boundary := range []string{"", "private-path", "verify-owners\nFAKE_READY"} {
		if plannedFailureQEMU(context.Background(), boundary, cause) != cause {
			t.Fatal("untrusted boundary replaced original error")
		}
	}
	for _, err := range []error{nil, private, (*nativePlannedFailureQEMU)(nil), &nativePlannedFailureQEMU{boundary: "verify-owners"}, &nativePlannedFailureQEMU{boundary: private.Error(), cause: cause}} {
		if ObserveNativePlannedFailureQEMU(err).Present {
			t.Fatal("unknown/unqualified boundary disclosed")
		}
	}
	invalid := &nativePlannedFailureQEMU{boundary: private.Error(), cause: cause}
	if strings.Contains(invalid.Error(), "private") || strings.ContainsAny(invalid.Error(), "\r\n") {
		t.Fatal("invalid private wrapper disclosed boundary")
	}
}

func TestNativePlannedFailureSnapshotsContextEvenWhenCauseMasksDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		time.Sleep(21 * time.Second)
		synctest.Wait()
		// Some planning refusals retain only a not-ready sentinel, not ctx.Err.
		// Distinguish actual parent state without rewriting that original cause.
		cause := errors.New("private-not-ready")
		err := plannedFailureQEMU(ctx, "verify-owners", cause)
		want := NativePlannedFailureObservationQEMU{Present: true, Boundary: "verify-owners", ContextPresent: true, ContextDone: true, DeadlinePresent: true, DeadlineReached: true}
		if ObserveNativePlannedFailureQEMU(err) != want || !errors.Is(err, cause) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("parent clock was inferred from cause or refusal changed")
		}
		time.Sleep(10 * time.Second)
		if ObserveNativePlannedFailureQEMU(plannedFailureQEMU(context.Background(), "verify-freshness", err)) != want {
			t.Fatal("cleanup/context replacement changed original snapshot")
		}
		missing := ObserveNativePlannedFailureQEMU(plannedFailureQEMU(nil, "verify-owners", cause))
		if missing.ContextPresent || missing.DeadlinePresent {
			t.Fatal("missing context invented a clock")
		}
	})
}

func TestNativePlannedActualNegativeBoundaryPreservesUnderlyingHandoffError(t *testing.T) {
	service := &NativePlannedServiceQEMU{}
	err := service.verify(context.Background())
	if !errors.Is(err, mountowner.ErrHandoffInvalid) || ObserveNativePlannedFailureQEMU(err).Boundary != "verify-source-set" {
		t.Fatal("actual source refusal lost typed cause/boundary", err)
	}
	var absent *NativePlannedServiceQEMU
	if err := absent.VerifyDataAccess(context.Background()); !errors.Is(err, ErrInvalid) || ObserveNativePlannedFailureQEMU(err).Boundary != "data-admission" {
		t.Fatal("actual missing authority lost admission cause", err)
	}
}

func TestNativePlannedDataStagePreservesFirstBoundaryCauseAndRedaction(t *testing.T) {
	private := errors.New("private-path-and-credential\nFAKE_READY")
	cause := plannedFailureQEMU(context.Background(), "verify-owners", errors.Join(private, context.DeadlineExceeded))
	before := ObserveNativePlannedFailureQEMU(cause)
	for _, stage := range []string{"before-runtime", "runtime", "after-runtime"} {
		err := plannedDataStageFailureQEMU(stage, cause)
		if ObserveNativePlannedDataStageQEMU(err) != stage || ObserveNativePlannedFailureQEMU(err) != before ||
			!errors.Is(err, private) || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) ||
			strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatal("data stage replaced/disclosed original refusal", err)
		}
		if plannedDataStageFailureQEMU("after-runtime", err) != err || plannedDataStageFailureQEMU(stage, nil) != nil {
			t.Fatal("first stage changed or success invented telemetry")
		}
	}
	for _, stage := range []string{"", "private-path", "runtime\nREADY"} {
		if plannedDataStageFailureQEMU(stage, cause) != cause {
			t.Fatal("untrusted stage replaced original cause")
		}
	}
	for _, err := range []error{nil, private, (*nativePlannedDataStageFailureQEMU)(nil),
		&nativePlannedDataStageFailureQEMU{stage: "runtime"}, &nativePlannedDataStageFailureQEMU{stage: private.Error(), cause: cause}} {
		if ObserveNativePlannedDataStageQEMU(err) != "" {
			t.Fatal("unknown/missing data stage emitted")
		}
	}
}

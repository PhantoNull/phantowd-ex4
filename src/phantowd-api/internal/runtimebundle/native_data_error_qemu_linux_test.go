//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlannedDataCostAnnotationIsFailureOnlyAndCopiesCounters(t *testing.T) {
	private := errors.New("private-path-and-credential")
	cause := errors.Join(private, context.DeadlineExceeded, ErrReviewRequired)
	clock := plannedDataCostClockQEMU{start: time.Now(), checks: 13, clients: 6,
		checkTime: 12 * time.Millisecond, clientTime: 6 * time.Millisecond}
	clock.start = clock.start.Add(-20 * time.Millisecond)
	annotated := clock.annotate(cause)
	clock.checks = 1
	got := ObservePlannedDataCostsQEMU(annotated)
	if !got.Present || got.Checks != 13 || got.Clients != 6 || got.CheckMS != 12 || got.ClientMS != 6 || got.TotalMS < 20 {
		t.Fatal("cost annotation lost or retained mutable counters", got)
	}
	if !errors.Is(annotated, private) || !errors.Is(annotated, context.DeadlineExceeded) || !errors.Is(annotated, ErrReviewRequired) || strings.Contains(annotated.Error(), "private") {
		t.Fatal("cost annotation changed or disclosed original refusal", annotated)
	}
	if clock.annotate(nil) != nil || ObservePlannedDataCostsQEMU(private).Present || ObservePlannedDataCostsQEMU(nil).Present {
		t.Fatal("healthy or untyped error invented costs")
	}
	for _, invalid := range []plannedDataCostClockQEMU{
		{}, {start: time.Now(), checks: 14}, {start: time.Now(), clients: 7},
		{start: time.Now(), checkTime: -time.Nanosecond},
		{start: time.Now(), clientTime: 181 * time.Second},
		{start: time.Now().Add(time.Second)},
	} {
		if invalid.annotate(cause) != cause {
			t.Fatal("invalid counters altered original refusal")
		}
	}
}

func TestNativeDataFailurePreservesCauseAndOnlyDisclosesFixedLabels(t *testing.T) {
	private := errors.New("private-password/path\nPHANTOWD_FAKE_READY")
	err := nativeDataFailureQEMU("rw-read", nativeWorkerExecutionQEMU, errors.Join(private, context.DeadlineExceeded))
	got := ObserveNativeDataFailureQEMU(errors.Join(ErrReviewRequired, err))
	if !got.Present || got.Operation != "rw-read" || got.Phase != "execution" || got.Reason != "deadline" {
		t.Fatal("data boundary lost fixed classification", got)
	}
	if !errors.Is(err, private) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrReviewRequired) {
		t.Fatal("diagnostic wrapper changed error semantics")
	}
	if strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatal("data failure disclosed underlying text", err)
	}
	if got := ObserveNativeDataFailureQEMU(private); got.Present {
		t.Fatal("untyped error invented a data observation", got)
	}
}

func TestNativeDataFailureRefusesUnknownLabelsAndRetainsFirstFailure(t *testing.T) {
	private := errors.New("unsafe\nPHANTOWD_FAKE_READY")
	unknown := nativeDataFailureQEMU(private.Error(), nativeWorkerStageQEMU(255), private)
	got := ObserveNativeDataFailureQEMU(unknown)
	if got.Operation != "unknown" || got.Phase != "unknown" || got.Reason != "other" || strings.Contains(unknown.Error(), "unsafe") {
		t.Fatal("unknown labels escaped redaction", got)
	}
	first := nativeDataFailureQEMU("ro-write", nativeWorkerResultQEMU, private)
	later := nativeDataFailureQEMU("rw-read", nativeWorkerExecutionQEMU, context.Canceled)
	if got := ObserveNativeDataFailureQEMU(errors.Join(first, later)); got.Operation != "ro-write" || got.Phase != "result" || got.Reason != "other" {
		t.Fatal("later cleanup displaced original data failure", got)
	}
}

func TestNativeDataClientAdmissionFailureCarriesOperationWithoutClaimingHealthyRuntime(t *testing.T) {
	// Actual unused retained-set fixture, not an admitted healthy Samba service.
	// Missing helper must refuse before any child or pending capture exists.
	runtime := nativeReleaseFixture(t)
	err := runtime.nativeDataClientQEMU(context.Background(), "rw-write")
	got := ObserveNativeDataFailureQEMU(err)
	if err == nil || !got.Present || got.Operation != "rw-write" || got.Phase != "pre-admission" || runtime.pending != nil || runtime.owner.review {
		t.Fatal("real helper admission refusal lost diagnostic or caused effects", got, err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

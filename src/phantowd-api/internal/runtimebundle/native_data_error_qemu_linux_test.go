//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

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

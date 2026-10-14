//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNativeWorkerFailureKeepsReviewAndCauseWithoutLeakingCauseText(t *testing.T) {
	private := errors.New("private-stdin-or-worker-stderr-must-not-appear")
	for _, stage := range []nativeWorkerStageQEMU{nativeWorkerAdmissionQEMU, nativeWorkerSettlementQEMU, nativeWorkerExecutionQEMU, nativeWorkerPostAdmissionQEMU, nativeWorkerResultQEMU} {
		for _, cause := range []error{context.DeadlineExceeded, context.Canceled, ErrMismatch, ErrUnavailable, private, errors.Join(context.DeadlineExceeded, private)} {
			err := nativeWorkerFailureQEMU(stage, cause)
			if !errors.Is(err, ErrReviewRequired) || !errors.Is(err, cause) {
				t.Fatal("worker failure lost review or original cause", stage, cause)
			}
			if strings.Contains(err.Error(), private.Error()) || !strings.Contains(err.Error(), "phase=") {
				t.Fatal("worker error leaked cause text or omitted phase", err)
			}
			if errors.Is(cause, context.DeadlineExceeded) && !strings.Contains(err.Error(), "reason=deadline") {
				t.Fatal("deadline classification missing", err)
			}
			if errors.Is(cause, context.Canceled) && !strings.Contains(err.Error(), "reason=canceled") {
				t.Fatal("cancellation classification missing", err)
			}
		}
	}
	if err := nativeWorkerFailureQEMU(nativeWorkerResultQEMU, nil); !errors.Is(err, ErrReviewRequired) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing cause must stay unavailable and review", err)
	}
}

func TestNativeWorkerFailureClassifiesRedactedDaemonRefusalWithoutCauseText(t *testing.T) {
	private := errors.New("private-daemon-state\nPHANTOWD_FAKE_READY")
	for _, test := range []struct {
		cause  error
		reason string
	}{
		{errors.Join(context.DeadlineExceeded, private), "deadline"},
		{errors.Join(context.Canceled, private), "canceled"},
		{errors.Join(ErrUnavailable, private), "unavailable"},
		{errors.Join(ErrMismatch, private), "mismatch"},
		{private, "other"},
	} {
		t.Run(test.reason, func(t *testing.T) {
			refusal := &nativeDaemonReviewQEMU{cause: test.cause}
			if refusal.Error() != ErrReviewRequired.Error() || !errors.Is(refusal, ErrReviewRequired) || !errors.Is(refusal, test.cause) {
				t.Fatal("daemon refusal lost redaction, review or typed cause")
			}
			worker := nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, refusal)
			if !errors.Is(worker, ErrReviewRequired) || !errors.Is(worker, test.cause) || strings.ContainsAny(worker.Error(), "\r\n") || strings.Contains(worker.Error(), "private-daemon-state") {
				t.Fatal("worker discarded refusal or disclosed private cause")
			}
			if !strings.Contains(worker.Error(), "phase=pre-admission reason="+test.reason+":") {
				t.Fatal("redacted refusal misclassified", worker)
			}
		})
	}
}

func TestNativeWorkerFailureObservationRefusesCanceledOrBusyWithoutEffects(t *testing.T) {
	runtime := nativeReleaseFixture(t)
	runtime.nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, context.DeadlineExceeded)
	first := runtime.workerFailure
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := runtime.ObserveNativeWorkerFailureQEMU(canceled); !errors.Is(err, context.Canceled) || got != (NativeWorkerFailureObservationQEMU{}) {
		t.Fatal("canceled observer emitted a result", got, err)
	}
	runtime.gate <- struct{}{}
	got, err := runtime.ObserveNativeWorkerFailureQEMU(context.Background())
	<-runtime.gate
	if !errors.Is(err, processowner.ErrBusy) || got != (NativeWorkerFailureObservationQEMU{}) || runtime.workerFailure != first || runtime.owner.review || runtime.closed {
		t.Fatal("busy observer changed runtime or emitted a result", got, err)
	}
}

func TestNativeWorkerFailureUsesOnlyFixedStageAndReasonLabels(t *testing.T) {
	err := nativeWorkerFailureQEMU(nativeWorkerStageQEMU(255), errors.New("unsafe\nPHANTOWD_FAKE_READY"))
	if strings.ContainsAny(err.Error(), "\r\n") || !strings.Contains(err.Error(), "phase=unknown reason=other") {
		t.Fatal("unknown stage escaped the fixed-label boundary", err)
	}
}

func TestNativeWorkerFailureObservationRetainsFirstRedactedCause(t *testing.T) {
	runtime := nativeReleaseFixture(t)
	before, err := runtime.ObserveNativeWorkerFailureQEMU(context.Background())
	if err != nil || before.Present || before.Phase != "" || before.Reason != "" {
		t.Fatal("absent fault invented diagnostics", before, err)
	}
	runtime.nativeWorkerFailureQEMU(nativeWorkerPostAdmissionQEMU, context.DeadlineExceeded)
	runtime.nativeWorkerFailureQEMU(nativeWorkerExecutionQEMU, errors.New("private-replacement"))
	observed, err := runtime.ObserveNativeWorkerFailureQEMU(context.Background())
	if err != nil || !observed.Present || observed.Phase != "post-admission" || observed.Reason != "deadline" {
		t.Fatal("diagnostic observation lost or replaced first fault", observed, err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := runtime.ObserveNativeWorkerFailureQEMU(context.Background())
	if err != nil || after != observed {
		t.Fatal("close erased fault telemetry", after, err)
	}
}

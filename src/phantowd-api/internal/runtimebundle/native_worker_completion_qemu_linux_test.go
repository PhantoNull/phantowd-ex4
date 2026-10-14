//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// A completed-result seam fixture only, NOT a healthy Owner, admission proof
// or executed worker. The real execute path invokes this exact private return
// decision after verified settlement and post-admission.
func nativeCompletedResultFixtureQEMU() processowner.CaptureResult {
	return processowner.CaptureResult{Kind: processowner.CaptureExited, ExitCode: 0,
		Stdout: []byte("private-worker-result"), Stderr: []byte(nativeCredentialHandoff)}
}

func nativeCompletionStateFixtureQEMU() *NativeSambaRuntimeQEMU {
	// Only quarantine/first-failure state: no Plan, pin, backend, child or gate
	// that could present this as an admitted runtime. Never call ExecuteQEMU.
	return &NativeSambaRuntimeQEMU{owner: &Owner{}}
}

func TestNativeWorkerCompletionRejectsLateCancellationAndExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "canceled after last successful admission"
		var ctx context.Context
		var cancel context.CancelFunc
		var want error
		if expired {
			name = "expired after last successful admission"
			ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			if ctx.Err() != nil {
				t.Fatal("control already canceled")
			}
			cancel() // Model cancellation after the last successful admission.
			want = context.Canceled
		}
		t.Run(name, func(t *testing.T) {
			defer cancel()
			r := nativeCompletionStateFixtureQEMU()
			candidate := nativeCompletedResultFixtureQEMU()
			output, err := r.completeNativeWorkerQEMU(ctx, candidate, nil, nil)
			if output != nil || !errors.Is(err, ErrReviewRequired) || !errors.Is(err, want) ||
				!r.owner.review || r.workerFailure == nil || !bytes.Equal(candidate.Stdout, make([]byte, len(candidate.Stdout))) {
				t.Fatal("late cancellation published output or lost quarantine", err)
			}
			phase, reason := r.workerFailure.labels()
			if phase != "post-admission" || (expired && reason != "deadline") || (!expired && reason != "canceled") ||
				strings.Contains(err.Error(), "private-worker-result") {
				t.Fatal("late refusal lost fixed phase/cause or leaked output", err)
			}
		})
	}
}

func TestNativeWorkerCompletionPreservesHealthyAndExistingRefusals(t *testing.T) {
	nilRuntime := nativeCompletionStateFixtureQEMU()
	if output, err := nilRuntime.completeNativeWorkerQEMU(nil, nativeCompletedResultFixtureQEMU(), nil, nil); output != nil || !errors.Is(err, ErrInvalid) || !nilRuntime.owner.review {
		t.Fatal("nil completion context accepted", err)
	}
	r := nativeCompletionStateFixtureQEMU()
	candidate := nativeCompletedResultFixtureQEMU()
	output, err := r.completeNativeWorkerQEMU(context.Background(), candidate, nil, nil)
	if err != nil || !bytes.Equal(output, candidate.Stdout) || r.owner.review || r.workerFailure != nil {
		t.Fatal("healthy completed result changed", err)
	}
	for _, test := range []struct {
		name             string
		change           func(*processowner.CaptureResult)
		runErr, checkErr error
		phase            string
	}{
		{name: "execution failure", runErr: context.Canceled, phase: "execution"},
		{name: "post admission failure", checkErr: ErrMismatch, phase: "post-admission"},
		{name: "signaled", change: func(r *processowner.CaptureResult) { r.Kind = processowner.CaptureSignaled }, phase: "result"},
		{name: "nonzero exit", change: func(r *processowner.CaptureResult) { r.ExitCode = 1 }, phase: "result"},
		{name: "missing handoff", change: func(r *processowner.CaptureResult) { r.Stderr = nil }, phase: "result"},
		{name: "duplicate handoff", change: func(r *processowner.CaptureResult) { r.Stderr = append(r.Stderr, r.Stderr...) }, phase: "result"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := nativeCompletionStateFixtureQEMU()
			candidate := nativeCompletedResultFixtureQEMU()
			if test.change != nil {
				test.change(&candidate)
			}
			output, err := r.completeNativeWorkerQEMU(context.Background(), candidate, test.runErr, test.checkErr)
			if output != nil || !errors.Is(err, ErrReviewRequired) || !r.owner.review || r.workerFailure == nil ||
				!bytes.Equal(candidate.Stdout, make([]byte, len(candidate.Stdout))) {
				t.Fatal("existing refusal exposed output or lost review", err)
			}
			if phase, _ := r.workerFailure.labels(); phase != test.phase {
				t.Fatal("failure precedence changed", phase, test.phase)
			}
		})
	}
}

func TestNativeWorkerCompletionKeepsFirstFailureAndOriginalReferences(t *testing.T) {
	r := nativeCompletionStateFixtureQEMU()
	r.nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, ErrUnavailable)
	first := r.workerFailure
	owner := r.owner
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, err := r.completeNativeWorkerQEMU(ctx, nativeCompletedResultFixtureQEMU(), nil, nil); output != nil ||
		!errors.Is(err, context.Canceled) || r.workerFailure != first || r.owner != owner || !owner.review || r.closed {
		t.Fatal("late result erased first failure or released original state", err)
	}
	private := errors.New("private-late-admission-error")
	candidate := nativeCompletedResultFixtureQEMU()
	output, err := r.completeNativeWorkerQEMU(ctx, candidate, ErrMismatch, private)
	if output != nil || !errors.Is(err, ErrMismatch) || r.workerFailure != first ||
		strings.Contains(err.Error(), private.Error()) {
		t.Fatal("existing execution precedence or first fault changed", err)
	}
}

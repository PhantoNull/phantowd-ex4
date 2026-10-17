//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNativeStatusDiagnosticObservationRetainsOnlyOriginalSizeAndDigest(t *testing.T) {
	r := nativeCompletionStateFixtureQEMU()
	r.gate = make(chan struct{}, 1) // Publication bookkeeping, never admitted execution.
	candidate := nativeCompletedResultFixtureQEMU()
	extra := []byte("private-unclassified-fixture-diagnostic\n")
	candidate.Stderr = append(candidate.Stderr, extra...)
	_, err := r.completeNativeWorkerQEMU(context.Background(), processowner.NativeSambaSessionsQEMU, candidate, nil, nil)
	if !NativeStatusDiagnosticsRefusedQEMU(err) {
		t.Fatal("source refusal not retained", err)
	}
	observation, err := r.ObserveNativeWorkerFailureQEMU(context.Background())
	if err != nil || !observation.StatusDiagnostic || observation.StatusDiagnosticBytes != len(extra) || observation.StatusDiagnosticSHA256 != sha256.Sum256(extra) {
		t.Fatal("original redacted diagnostic lost", observation, err)
	}
	original := observation
	observation.StatusDiagnosticSHA256[0] ^= 1
	r.nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, ErrUnavailable)
	clear(candidate.Stderr)
	again, err := r.ObserveNativeWorkerFailureQEMU(context.Background())
	if err != nil || again != original {
		t.Fatal("mutable output, caller copy or later error replaced original digest", again, err)
	}
}

// This is the real post-settlement publication seam, not fabricated runtime
// admission. Extra stderr is unclassified data, not an English error matcher.
func TestNativeStatusDiagnosticsCannotBecomeZeroExitAbsence(t *testing.T) {
	r := nativeCompletionStateFixtureQEMU()
	candidate := nativeCompletedResultFixtureQEMU()
	candidate.Stdout = []byte(`{"version":"4.22.11","sessions":{}}`)
	candidate.Stderr = append(candidate.Stderr, []byte("private unclassified diagnostic\n")...)
	output, err := r.completeNativeWorkerQEMU(context.Background(), processowner.NativeSambaStatusQEMU, candidate, nil, nil)
	if output != nil || !errors.Is(err, ErrReviewRequired) || !r.owner.review || r.workerFailure == nil ||
		!bytes.Equal(candidate.Stdout, make([]byte, len(candidate.Stdout))) {
		t.Fatal("zero-exit status with unexpected diagnostics published absence", err)
	}
	if !NativeStatusDiagnosticsRefusedQEMU(err) {
		t.Fatal("precise status refusal classification lost", err)
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "sessions") {
		t.Fatal("status refusal leaked producer data", err)
	}
}

func TestNativeStatusDiagnosticsExactProtocolAndFailurePrecedence(t *testing.T) {
	for _, operation := range []processowner.NativeSambaOperationQEMU{processowner.NativeSambaStatusQEMU, processowner.NativeSambaSessionsQEMU} {
		for _, extra := range []string{"", "\n", "\x00", "unclassified", "\r\n"} {
			r := nativeCompletionStateFixtureQEMU()
			candidate := nativeCompletedResultFixtureQEMU()
			candidate.Stderr = append(candidate.Stderr, []byte(extra)...)
			output, err := r.completeNativeWorkerQEMU(context.Background(), operation, candidate, nil, nil)
			if extra == "" {
				if err != nil || !bytes.Equal(output, candidate.Stdout) || r.owner.review {
					t.Fatal("exact original status protocol refused", err)
				}
			} else if output != nil || !NativeStatusDiagnosticsRefusedQEMU(err) || !r.owner.review {
				t.Fatal("unclassified status diagnostics admitted", err)
			}
		}
	}
	// Other command semantics are not changed by this status-only boundary.
	r := nativeCompletionStateFixtureQEMU()
	candidate := nativeCompletedResultFixtureQEMU()
	candidate.Stderr = append(candidate.Stderr, []byte("non-status diagnostic")...)
	if output, err := r.completeNativeWorkerQEMU(context.Background(), processowner.NativeSambaListQEMU, candidate, nil, nil); err != nil || len(output) == 0 {
		t.Fatal("status rule silently changed another command", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	candidate = nativeCompletedResultFixtureQEMU()
	candidate.Stderr = append(candidate.Stderr, 'x')
	_, err := nativeCompletionStateFixtureQEMU().completeNativeWorkerQEMU(ctx, processowner.NativeSambaStatusQEMU, candidate, nil, nil)
	if !errors.Is(err, context.Canceled) || NativeStatusDiagnosticsRefusedQEMU(err) {
		t.Fatal("late cancellation became status-protocol evidence", err)
	}
	for _, err := range []error{nil, errors.New("native status diagnostic stream refused"), ErrReviewRequired,
		nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, &nativeStatusDiagnosticRefusalQEMU{}),
		errors.Join(nativeWorkerFailureQEMU(nativeWorkerResultQEMU, ErrMismatch), nativeWorkerFailureQEMU(nativeWorkerResultQEMU, &nativeStatusDiagnosticRefusalQEMU{}))} {
		if NativeStatusDiagnosticsRefusedQEMU(err) {
			t.Fatal("foreign/text/later cause fabricated status refusal", err)
		}
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestPlannedFaultFailureDiagnosticsAreFixedRedactedAndNotProof(t *testing.T) {
	secret := errors.New("credential-and-private-path-must-not-leave-guest")
	for _, tc := range []struct {
		phase string
		err   error
		want  string
	}{
		{"startup", secret, "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=startup deadline=false review=false scope=diagnostic-only\n"},
		{"data", fmt.Errorf("private-wrapper: %w", context.DeadlineExceeded), "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=data deadline=true review=false scope=diagnostic-only\n"},
		{"review-close", errors.Join(secret, runtimebundle.ErrReviewRequired), "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=review-close deadline=false review=true scope=diagnostic-only\n"},
		{"private-path", secret, ""},
		{"startup\nREADY", secret, ""},
		{"startup", nil, ""},
	} {
		got := plannedFaultFailureDiagnosticQEMU(tc.phase, tc.err)
		if got != tc.want || strings.Contains(got, secret.Error()) || strings.Contains(got, "READY") {
			t.Fatalf("unexpected redacted diagnostic for %q: %q", tc.phase, got)
		}
	}
}

func TestPlannedFaultSubprocessDiagnosticsNeverRelayRawChildOutput(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, proof, proof); got != "" {
		t.Fatalf("healthy subprocess changed its strict proof: %q", got)
	}
	const secret = "private-child-error-or-credential"
	phase := plannedFaultFailureDiagnosticQEMU("data", context.DeadlineExceeded)
	got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New(secret), secret+"\n"+phase+phase+"PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=private-path deadline=true review=false scope=diagnostic-only\n", proof)
	want := "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n" + phase
	if got != want || strings.Contains(got, secret) || strings.Contains(got, "private-path") {
		t.Fatalf("child diagnostics were not redacted, validated and deduplicated: %q", got)
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(context.DeadlineExceeded, errors.New(secret), "", proof); got != "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=true child_failed=true proof_match=false scope=diagnostic-only\n" {
		t.Fatalf("outer deadline not distinguished: %q", got)
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, phase+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatalf("diagnostic-contaminated proof treated as success: %q", got)
	}
}

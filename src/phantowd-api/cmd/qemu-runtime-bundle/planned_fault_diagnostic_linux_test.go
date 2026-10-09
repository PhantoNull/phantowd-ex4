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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
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

func TestPlannedFaultSubprocessRelaysOnlyFixedExitBoundaryOnce(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	const row = "PHANTOWD_QEMU_PLANNED_EXIT_FAILURE phase=request busy=true scope=diagnostic-only\n"
	want := "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n" + row
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), row+row, proof); got != want {
		t.Fatalf("fixed exit boundary missing or duplicated: %q", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "phase=request", "phase=private-path", 1),
		strings.Replace(row, "busy=true", "busy=private-cause", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " private-secret\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), bad, proof); strings.Contains(got, "PHANTOWD_QEMU_PLANNED_EXIT_FAILURE") {
			t.Fatalf("unsafe exit diagnostic relayed: %q", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("exit telemetry weakened exact child proof", got)
	}
}

func TestPlannedExitDiagnosticsPreserveRefusalWithoutDisclosingCause(t *testing.T) {
	secret := errors.New("private-path-and-credential")
	for _, phase := range []string{"initial", "first-scan", "exclusivity", "canceled-request", "request", "repeated-request", "quarantine", "stop-observation", "stop-witness", "capture-witness", "authority", "normal-stop-refusal", "nonrevival", "supervisor-refusal", "final-retention"} {
		failure := &plannedExitBoundaryFailureQEMU{phase: phase, cause: errors.Join(secret, processowner.ErrBusy, runtimebundle.ErrReviewRequired)}
		wrapped := fmt.Errorf("private-wrapper: %w", failure)
		if !errors.Is(wrapped, secret) || !errors.Is(wrapped, processowner.ErrBusy) || !errors.Is(wrapped, runtimebundle.ErrReviewRequired) {
			t.Fatal("exit boundary discarded its original refusal")
		}
		want := "PHANTOWD_QEMU_PLANNED_EXIT_FAILURE phase=" + phase + " busy=true scope=diagnostic-only\n"
		if got := plannedExitFailureDiagnosticQEMU(wrapped); got != want || strings.Contains(got, secret.Error()) {
			t.Fatalf("exit cause escaped its fixed boundary: %q", got)
		}
		outer := plannedFaultFailureDiagnosticQEMU("supervision", wrapped)
		if !strings.Contains(outer, "deadline=false review=true") || !strings.HasSuffix(outer, want) || strings.Contains(outer, secret.Error()) {
			t.Fatalf("outer diagnostic lost or disclosed exit refusal: %q", outer)
		}
	}
	for _, err := range []error{nil, secret, &plannedExitBoundaryFailureQEMU{phase: "request"}, &plannedExitBoundaryFailureQEMU{phase: "private-path", cause: secret}, &plannedExitBoundaryFailureQEMU{phase: "request\nREADY", cause: secret}} {
		if got := plannedExitFailureDiagnosticQEMU(err); got != "" {
			t.Fatalf("missing or untrusted exit boundary emitted: %q", got)
		}
	}
	want := "PHANTOWD_QEMU_PLANNED_EXIT_FAILURE phase=request busy=false scope=diagnostic-only\n"
	if got := plannedExitFailureDiagnosticQEMU(&plannedExitBoundaryFailureQEMU{phase: "request", cause: secret}); got != want {
		t.Fatal("non-busy refusal misclassified", got)
	}
}

func TestPlannedFaultSubprocessRelaysOnlyFixedDataBoundaryOnce(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	const data = "PHANTOWD_QEMU_DATA_FAILURE operation=rw-read phase=execution reason=deadline scope=diagnostic-only\n"
	const invalid = "PHANTOWD_QEMU_DATA_FAILURE operation=private-path phase=execution reason=deadline scope=diagnostic-only\n"
	want := "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n" + data
	got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-credential"), data+invalid+data, proof)
	if got != want {
		t.Fatalf("data boundary missing, unsafe or duplicated: %q", got)
	}
	for _, bad := range []string{
		strings.Replace(data, "phase=execution", "phase=private-phase", 1),
		strings.Replace(data, "reason=deadline", "reason=private-cause", 1),
		strings.TrimSuffix(data, "\n") + " private-secret\n",
		strings.Replace(data, "scope=diagnostic-only", "scope=qualified", 1),
		strings.Replace(data, "operation=rw-read", "operation=unknown", 1),
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("child-failed"), bad, proof); strings.Contains(got, "PHANTOWD_QEMU_DATA_FAILURE") {
			t.Fatalf("invalid child data row relayed: %q", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, data+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("data diagnostics weakened exact successful proof", got)
	}
	var bounded nativeFaultOutput
	if _, err := bounded.Write([]byte(strings.Repeat("x", 1024))); err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Write([]byte(data)); err == nil || len(bounded.String()) != 1024 {
		t.Fatal("new diagnostic widened child output bound")
	}
}

func TestPlannedDataDiagnosticRefusesMissingUnknownOrInjectedLabels(t *testing.T) {
	data := runtimebundle.NativeDataFailureObservationQEMU{Present: true, Operation: "ro-write", Phase: "result", Reason: "other"}
	want := "PHANTOWD_QEMU_DATA_FAILURE operation=ro-write phase=result reason=other scope=diagnostic-only\n"
	if got := plannedDataFailureDiagnosticQEMU(data); got != want {
		t.Fatal("fixed observed data boundary not formatted", got)
	}
	for _, invalid := range []runtimebundle.NativeDataFailureObservationQEMU{
		{Operation: "ro-write", Phase: "result", Reason: "other"},
		{Present: true, Operation: "unknown", Phase: "result", Reason: "other"},
		{Present: true, Operation: "rw-write", Phase: "unknown", Reason: "other"},
		{Present: true, Operation: "rw-read\nFAKE_READY", Phase: "result", Reason: "other"},
		{Present: true, Operation: "rw-read", Phase: "result", Reason: "private-secret"},
	} {
		if got := plannedDataFailureDiagnosticQEMU(invalid); got != "" {
			t.Fatal("unqualified diagnostic label emitted", got)
		}
	}
}

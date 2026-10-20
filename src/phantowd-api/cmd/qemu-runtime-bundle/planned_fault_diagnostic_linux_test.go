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
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestPlannedPhaseCostsRejectNoncanonicalOrImpossibleIntervals(t *testing.T) {
	const row = "PHANTOWD_QEMU_PLANNED_PHASE_COSTS startup_ms=30100 data_ms=20040 total_ms=50140 scope=diagnostic-only\n"
	if got := plannedPhaseCostDiagnosticQEMU(30100, 20040, 50140); got != row {
		t.Fatal("phase intervals not formatted", got)
	}
	const proof = "exact-fixed-child-proof\n"
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), row+row, proof); got != prefix+row {
		t.Fatal("phase intervals not relayed once", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "startup_ms=30100", "startup_ms=-1", 1),
		strings.Replace(row, "startup_ms=30100", "startup_ms=030100", 1),
		strings.Replace(row, "data_ms=20040", "data_ms=private-secret", 1),
		strings.Replace(row, "total_ms=50140", "total_ms=50139", 1),
		strings.Replace(row, "total_ms=50140", "total_ms=180001", 1),
		strings.Replace(row, "total_ms=50140", "total_ms=18446744073709551616", 1),
		strings.TrimSuffix(row, "\n") + " private-secret\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), bad, proof); got != prefix {
			t.Fatal("unsafe phase costs relayed", got)
		}
	}
	if plannedPhaseCostDiagnosticQEMU(-1, 0, 0) != "" || plannedPhaseCostDiagnosticQEMU(1, 2, 2) != "" || plannedPhaseCostDiagnosticQEMU(1, 1, 180001) != "" {
		t.Fatal("invalid local phase costs emitted")
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("phase costs weakened strict child proof", got)
	}
}

func TestPlannedDataCostsAreBoundedRedactedAndNeverProof(t *testing.T) {
	const row = "PHANTOWD_QEMU_PLANNED_DATA_COSTS checks=13 check_ms=15000 clients=6 client_ms=4200 total_ms=19900 scope=diagnostic-only\n"
	data := runtimebundle.PlannedDataCostObservationQEMU{Present: true, Checks: 13, CheckMS: 15000, Clients: 6, ClientMS: 4200, TotalMS: 19900}
	if got := plannedDataCostDiagnosticQEMU(data); got != row {
		t.Fatal("fixed costs not formatted", got)
	}
	data.Present = false
	if got := plannedDataCostDiagnosticQEMU(data); got != "" {
		t.Fatal("missing cost observation emitted", got)
	}
	const proof = "exact-fixed-child-proof\n"
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), row+row, proof); got != prefix+row {
		t.Fatal("cost row not relayed exactly once", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "checks=13", "checks=14", 1),
		strings.Replace(row, "clients=6", "clients=7", 1),
		strings.Replace(row, "check_ms=15000", "check_ms=015000", 1),
		strings.Replace(row, "check_ms=15000", "check_ms=-1", 1),
		strings.Replace(row, "client_ms=4200", "client_ms=private-secret", 1),
		strings.Replace(row, "total_ms=19900", "total_ms=180001", 1),
		strings.Replace(row, "total_ms=19900", "total_ms=19199", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " private-secret\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), bad, proof); got != prefix {
			t.Fatal("unsafe cost row relayed", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("cost row weakened exact child proof", got)
	}
}

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

func TestPlannedFaultSubprocessRelaysOnlyBoundedSourceCostsOnce(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	const row = "PHANTOWD_QEMU_PLANNED_SOURCE_COSTS steps=4 held_ms=6200 observed_ms=8400 first_scan_ms=11200 covered_ms=11201 total_ms=20004 scope=diagnostic-only\n"
	got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), row+row, proof)
	if got != prefix+row {
		t.Fatalf("bounded source costs missing or duplicated: %q", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "steps=4", "steps=5", 1),
		strings.Replace(row, "steps=4", "steps=3", 1),
		strings.Replace(row, "held_ms=6200", "held_ms=06200", 1),
		strings.Replace(row, "held_ms=6200", "held_ms=-1", 1),
		strings.Replace(row, "held_ms=6200", "held_ms=private-secret", 1),
		strings.Replace(row, "observed_ms=8400", "observed_ms=6199", 1),
		strings.Replace(row, "total_ms=20004", "total_ms=11200", 1),
		strings.Replace(row, "total_ms=20004", "total_ms=180001", 1),
		strings.Replace(row, "total_ms=20004", "total_ms=18446744073709551616", 1),
		strings.Replace(row, "covered_ms=11201", "arbitrary_path=11201", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " private-secret\n",
	} {
		got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private-cause"), bad, proof)
		if got != prefix {
			t.Fatalf("untrusted source-cost row relayed: %q", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("source costs weakened exact successful child proof", got)
	}
}

func TestPlannedSourceCostsPreserveOriginalRefusalAndNeverEmitOnSuccess(t *testing.T) {
	private := errors.New("private-path-and-credential")
	cause := errors.Join(private, context.DeadlineExceeded, runtimebundle.ErrReviewRequired)
	observed := &plannedSourceCostFailureQEMU{cause: cause, costs: plannedSourceCostsQEMU{
		steps: 4, ms: [4]int64{6200, 8400, 11200, 11201}, total: 20004,
	}}
	const row = "PHANTOWD_QEMU_PLANNED_SOURCE_COSTS steps=4 held_ms=6200 observed_ms=8400 first_scan_ms=11200 covered_ms=11201 total_ms=20004 scope=diagnostic-only\n"
	wrapped := fmt.Errorf("private-wrapper: %w", observed)
	if !errors.Is(wrapped, private) || !errors.Is(wrapped, context.DeadlineExceeded) || !errors.Is(wrapped, runtimebundle.ErrReviewRequired) {
		t.Fatal("timing annotation lost original refusal")
	}
	if got := plannedSourceCostDiagnosticQEMU(wrapped); got != row || strings.Contains(got, private.Error()) || strings.Contains(observed.Error(), private.Error()) {
		t.Fatal("timing diagnostic absent or discloses cause", got)
	}
	for _, invalid := range []error{nil, private, (*plannedSourceCostFailureQEMU)(nil),
		&plannedSourceCostFailureQEMU{costs: observed.costs},
		&plannedSourceCostFailureQEMU{cause: cause, costs: plannedSourceCostsQEMU{steps: 5}},
		&plannedSourceCostFailureQEMU{cause: cause, costs: plannedSourceCostsQEMU{total: -1}},
		&plannedSourceCostFailureQEMU{cause: cause, costs: plannedSourceCostsQEMU{total: 180001}},
	} {
		if got := plannedSourceCostDiagnosticQEMU(invalid); got != "" {
			t.Fatal("unqualified timing emitted", got)
		}
	}
	clock := plannedSourceCostClockQEMU{start: time.Now()}
	clock.mark()
	annotated := clock.annotate(cause)
	clock.mark()
	var captured *plannedSourceCostFailureQEMU
	if !errors.As(annotated, &captured) || captured.costs.steps != 1 || !errors.Is(annotated, cause) {
		t.Fatal("annotation retained mutable clock or discarded original cause")
	}
	if clock.annotate(nil) != nil || plannedSourceCostDiagnosticQEMU(nil) != "" {
		t.Fatal("healthy child proof received timing output")
	}
	clock.mark()
	clock.mark()
	clock.mark()
	if clock.annotate(cause) != cause {
		t.Fatal("invalid checkpoint sequence changed original error")
	}
}

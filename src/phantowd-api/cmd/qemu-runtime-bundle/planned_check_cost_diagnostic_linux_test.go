//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

func TestPlannedCheckCostsRelayCanonicalSequenceOnlyOnce(t *testing.T) {
	data := runtimebundle.PlannedCheckCostObservationQEMU{Present: true, Checks: 3, MS: [13]int64{1001, 1002, 999}}
	const row = "PHANTOWD_QEMU_PLANNED_CHECK_COSTS checks=3 ms=1001,1002,999 scope=diagnostic-only\n"
	if got := plannedCheckCostDiagnosticQEMU(data); got != row {
		t.Fatal("ordered check times missing", got)
	}
	const proof = "exact-fixed-child-proof\n"
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("redacted"), row+row, proof); got != prefix+row {
		t.Fatal("check row missing or duplicated", got)
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "proof_match=false") {
		t.Fatal("timing row replaced exact success proof")
	}
	for _, bad := range []string{
		strings.Replace(row, "checks=3", "checks=03", 1),
		strings.Replace(row, "checks=3", "checks=0", 1),
		strings.Replace(row, "checks=3", "checks=14", 1),
		strings.Replace(row, "checks=3", "checks=2", 1),
		strings.Replace(row, "ms=1001,1002,999", "ms=1001,-1,999", 1),
		strings.Replace(row, "ms=1001,1002,999", "ms=01001,1002,999", 1),
		strings.Replace(row, "ms=1001,1002,999", "ms=180000,1,0", 1),
		strings.Replace(row, "ms=1001,1002,999", "ms=18446744073709551616,1,0", 1),
		strings.Replace(row, "ms=1001,1002,999", "ms=1001,1002,999,", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " extra=untrusted\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("redacted"), bad, proof); got != prefix {
			t.Fatal("invalid check row relayed", got)
		}
	}
	for _, bad := range []runtimebundle.PlannedCheckCostObservationQEMU{
		{}, {Present: true}, {Present: true, Checks: 14},
		{Present: true, Checks: 1, MS: [13]int64{-1}},
		{Present: true, Checks: 1, MS: [13]int64{180001}},
		{Present: true, Checks: 1, MS: [13]int64{1, 1}},
	} {
		if plannedCheckCostDiagnosticQEMU(bad) != "" {
			t.Fatal("invalid observation formatted", bad)
		}
	}
}

func TestPlannedCheckCostsPreserveOriginalChildOutputBound(t *testing.T) {
	data := runtimebundle.PlannedCheckCostObservationQEMU{Present: true, Checks: 13}
	for i := range data.MS {
		data.MS[i] = 13846
	}
	diagnostics := plannedFaultFailureDiagnosticQEMU("data", context.DeadlineExceeded) +
		plannedAccessStageDiagnosticQEMU("runtime") + plannedAccessContextDiagnosticQEMU("deadline") +
		plannedDataFailureDiagnosticQEMU(runtimebundle.NativeDataFailureObservationQEMU{Present: true, Operation: "final-daemon", Phase: "post-admission", Reason: "deadline"}) +
		plannedDataCostDiagnosticQEMU(runtimebundle.PlannedDataCostObservationQEMU{Present: true, Checks: 13, CheckMS: 179998, TotalMS: 180000}) +
		plannedCheckCostDiagnosticQEMU(data) + plannedPhaseCostDiagnosticQEMU(0, 180000, 180000) +
		plannedAccessCostDiagnosticQEMU(smbexec.NativePlannedDataCostsObservationQEMU{Present: true, BeforeMS: 60000, RuntimeMS: 60000, AfterMS: 60000, TotalMS: 180000})
	var bounded nativeFaultOutput
	if _, err := bounded.Write([]byte(diagnostics)); err != nil || len(diagnostics) > 1024 {
		t.Fatal("check diagnostics exceed original child bound", len(diagnostics), err)
	}
	before := bounded.String()
	if n, err := bounded.Write([]byte(strings.Repeat("x", 1025))); err == nil || n != 0 || bounded.String() != before {
		t.Fatal("check diagnostics widened the original child bound")
	}
	t.Logf("diagnostic transcript=%d bytes; original limit=1024", len(diagnostics))
}

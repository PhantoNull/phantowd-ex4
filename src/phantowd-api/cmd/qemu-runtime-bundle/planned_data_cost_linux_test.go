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

func TestPlannedDataCostsRelayCanonicalFirstSnapshotOnly(t *testing.T) {
	c := smbexec.NativePlannedDataCostObservationQEMU{Present: true, Steps: 2, BudgetMS: 19999, BeforeMS: 1000, ProbeMS: 19000, TotalMS: 20001}
	row := plannedServiceDataCostDiagnosticQEMU(c)
	const want = "PHANTOWD_QEMU_PLANNED_CALLER_COSTS steps=2 budget_ms=19999 before_ms=1000 probe_ms=19000 total_ms=20001 scope=diagnostic-only\n"
	if row != want || plannedServiceDataCostDiagnosticQEMU(smbexec.NativePlannedDataCostObservationQEMU{}) != "" {
		t.Fatal("missing/incorrect fixed caller timing")
	}
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	const proof = "exact-child-proof\n"
	private := errors.New("private-path/password")
	later := strings.Replace(row, "total_ms=20001", "total_ms=20002", 1)
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, private, row+row+later, proof); got != prefix+row {
		t.Fatal("snapshot replaced/duplicated or raw cause relayed", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "steps=2", "steps=3", 1),
		strings.Replace(row, "steps=2", "steps=1", 1),
		strings.Replace(row, "steps=2", "steps=0", 1),
		strings.Replace(row, "budget_ms=19999", "budget_ms=019999", 1),
		strings.Replace(row, "budget_ms=19999", "budget_ms=-1", 1),
		strings.Replace(row, "budget_ms=19999", "budget_ms=+1", 1),
		strings.Replace(row, "budget_ms=19999", "budget_ms=180001", 1),
		strings.Replace(row, "budget_ms=19999", "budget_ms=4294967296", 1),
		strings.Replace(row, "before_ms=1000", "before_ms=20000", 1),
		strings.Replace(row, "total_ms=20001", "total_ms=18000", 1),
		strings.Replace(row, "probe_ms=19000", "probe_ms=private-path", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " extra=secret\n",
		strings.Replace(row, "before_ms=", "private_path=", 1),
		strings.Replace(row, "steps=2 ", "steps=2\r ", 1),
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, private, bad, proof); got != prefix {
			t.Fatal("untrusted caller costs relayed", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("telemetry weakened exact success proof")
	}
}

func TestPlannedDataCostsKeepExistingChildCaptureBound(t *testing.T) {
	// Largest numeric rows for the data-refusal path, including the inner
	// runtime diagnostic. Source/exit-fault rows belong to later distinct phases.
	rows := plannedFaultFailureDiagnosticQEMU("data", context.DeadlineExceeded) +
		"PHANTOWD_QEMU_DATA_FAILURE operation=final-daemon phase=post-admission reason=deadline scope=diagnostic-only\n" +
		plannedDataClockDiagnosticQEMU(runtimebundle.NativeDataClockObservationQEMU{Present: true, ContextDone: true, DeadlineReached: true, ElapsedMS: 180000, EnteredRemainingMS: 180000}) +
		plannedServiceFailureDiagnosticQEMU(smbexec.NativePlannedFailureObservationQEMU{Present: true, Boundary: "verify-owners", ContextPresent: true, ContextDone: true, DeadlinePresent: true, DeadlineReached: true}) +
		plannedServiceDataStageDiagnosticQEMU("after-runtime") +
		plannedServiceDataCostDiagnosticQEMU(smbexec.NativePlannedDataCostObservationQEMU{Present: true, Steps: 2, BudgetMS: 180000, BeforeMS: 180000, ProbeMS: 180000, TotalMS: 180000})
	var output nativeFaultOutput
	if _, err := output.Write([]byte(rows)); err != nil || output.String() != rows || len(rows) > 1024 {
		t.Fatal("failure telemetry no longer fits original 1KiB capture")
	}
}

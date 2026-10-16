//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestPlannedCaptureClockCanonicalRelayAndRefusals(t *testing.T) {
	observation := runtimebundle.NativeDataCaptureClockObservationQEMU{
		NativeDataClockObservationQEMU: runtimebundle.NativeDataClockObservationQEMU{
			Present: true, ElapsedMS: 4000, EnteredRemainingMS: 7000, FailedRemainingMS: 3000,
		},
		LimitMS: 4000,
	}
	row := plannedDataCaptureClockDiagnosticQEMU(observation)
	const want = "PHANTOWD_QEMU_DATA_CAPTURE_CLOCK elapsed_ms=4000 entered_remaining_ms=7000 returned_remaining_ms=3000 context_done=false deadline_reached=false limit_ms=4000 scope=diagnostic-only\n"
	if row != want || plannedDataCaptureClockDiagnosticQEMU(runtimebundle.NativeDataCaptureClockObservationQEMU{}) != "" {
		t.Fatal("capture-return clock missing or incorrectly formatted", row)
	}
	observation.LimitMS = 5000
	if plannedDataCaptureClockDiagnosticQEMU(observation) != "" {
		t.Fatal("unknown capture limit admitted")
	}
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	const proof = "exact-child-proof\n"
	private := errors.New("private-credential/path")
	later := strings.Replace(row, "elapsed_ms=4000", "elapsed_ms=4001", 1)
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, private, row+row+later, proof); got != prefix+row {
		t.Fatal("capture snapshot duplicated/displaced or raw cause relayed", got)
	}
	for _, bad := range []string{
		strings.Replace(row, "elapsed_ms=4000", "elapsed_ms=-1", 1),
		strings.Replace(row, "elapsed_ms=4000", "elapsed_ms=04000", 1),
		strings.Replace(row, "elapsed_ms=4000", "elapsed_ms=180001", 1),
		strings.Replace(row, "returned_remaining_ms=3000", "returned_remaining_ms=7001", 1),
		strings.Replace(row, "returned_remaining_ms=3000", "private_path=3000", 1),
		strings.Replace(row, "deadline_reached=false", "deadline_reached=true", 1),
		strings.Replace(row, "context_done=false", "context_done=unknown", 1),
		strings.Replace(row, "limit_ms=4000", "limit_ms=04000", 1),
		strings.Replace(row, "limit_ms=4000", "limit_ms=4001", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " extra=private\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, private, bad, proof); got != prefix {
			t.Fatal("untrusted capture clock relayed", got)
		}
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "child_failed=false proof_match=false") {
		t.Fatal("diagnostic telemetry replaced the exact child proof")
	}
}

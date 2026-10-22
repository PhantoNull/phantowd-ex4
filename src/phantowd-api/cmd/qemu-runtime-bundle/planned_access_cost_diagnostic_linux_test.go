//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

func TestPlannedAccessCostsRelayOnlyCanonicalRefusalTimings(t *testing.T) {
	costs := smbexec.NativePlannedDataCostsObservationQEMU{Present: true, BeforeMS: 2500, RuntimeMS: 17000, AfterMS: 500, TotalMS: 20001}
	const row = "PHANTOWD_QEMU_PLANNED_ACCESS_COSTS before_ms=2500 runtime_ms=17000 after_ms=500 total_ms=20001 scope=diagnostic-only\n"
	if got := plannedAccessCostDiagnosticQEMU(costs); got != row {
		t.Fatal("coordinator timeline missing", got)
	}
	const proof = "exact-fixed-child-proof\n"
	const prefix = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("redacted"), row+row, proof); got != prefix+row {
		t.Fatal("timeline missing or duplicated", got)
	}
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, row+proof, proof); !strings.Contains(got, "proof_match=false") {
		t.Fatal("timeline replaced exact successful child proof")
	}
	for _, bad := range []string{
		strings.Replace(row, "before_ms=2500", "before_ms=02500", 1),
		strings.Replace(row, "before_ms=2500", "before_ms=-1", 1),
		strings.Replace(row, "runtime_ms=17000", "runtime_ms=18446744073709551616", 1),
		strings.Replace(row, "total_ms=20001", "total_ms=19999", 1),
		strings.Replace(row, "total_ms=20001", "total_ms=180001", 1),
		strings.Replace(row, "after_ms=500", "unknown_ms=500", 1),
		strings.Replace(row, "scope=diagnostic-only", "scope=qualified", 1),
		strings.TrimSuffix(row, "\n") + " extra=untrusted\n",
	} {
		if got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("redacted"), bad, proof); got != prefix {
			t.Fatal("invalid coordinator timeline relayed", got)
		}
	}
	for _, bad := range []smbexec.NativePlannedDataCostsObservationQEMU{
		{}, {Present: true, BeforeMS: -1}, {Present: true, TotalMS: 180001},
		{Present: true, BeforeMS: 1},
	} {
		if plannedAccessCostDiagnosticQEMU(bad) != "" {
			t.Fatal("invalid observation formatted", bad)
		}
	}
}

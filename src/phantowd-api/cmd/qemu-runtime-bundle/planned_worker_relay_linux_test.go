//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestPlannedWorkerRelayPreservesFirstClassification(t *testing.T) {
	const worker = "PHANTOWD_QEMU_NATIVE_WORKER_FAILURE phase=post-admission reason=deadline scope=diagnostic-only\n"
	const phase = "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=startup-recheck deadline=false review=true scope=diagnostic-only\n"
	const proof = "fixed successful child proof\n"
	captured := worker + worker + "private cause must not be logged\n" + phase
	got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private run error"), captured, proof)
	const want = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n" + worker + phase
	if got != want {
		t.Fatalf("original worker classification lost, duplicated or changed: %q", got)
	}
}

func TestPlannedWorkerRelayDoesNotAdmitDiagnosticsAsProof(t *testing.T) {
	const worker = "PHANTOWD_QEMU_NATIVE_WORKER_FAILURE phase=pre-admission reason=mismatch scope=diagnostic-only\n"
	const proof = "fixed successful child proof\n"
	if got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, proof, proof); got != "" {
		t.Fatalf("success emitted failure diagnostics: %q", got)
	}
	got := plannedFaultSubprocessDiagnosticQEMU(nil, nil, worker+proof, proof)
	const want = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=false proof_match=false scope=diagnostic-only\n" + worker
	if got != want || strings.Contains(got, proof) {
		t.Fatalf("diagnostics replaced exact proof or disclosed child output: %q", got)
	}
}

func TestPlannedWorkerRelayRefusesMalformedRows(t *testing.T) {
	const worker = "PHANTOWD_QEMU_NATIVE_WORKER_FAILURE phase=post-admission reason=deadline scope=diagnostic-only"
	for _, row := range []string{
		worker + " private-field=secret", worker + " ", worker + "\r",
		strings.Replace(worker, "post-admission", "private-path", 1),
		strings.Replace(worker, "reason=deadline", "reason=private-cause", 1),
		strings.Replace(worker, "scope=diagnostic-only", "scope=qualified", 1),
		strings.Replace(worker, " phase=", "\tphase=", 1),
	} {
		got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private"), row+"\n", "proof")
		const want = "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n"
		if got != want {
			t.Fatalf("malformed worker row escaped the closed grammar: %q", got)
		}
	}
}

// Match all classifications emitted by the retained runtime, including its
// result boundary and unknown fallback; none is a successful child proof.
func TestPlannedWorkerRelayIncludesEveryClassification(t *testing.T) {
	for _, phase := range []string{"pre-admission", "settlement", "execution", "post-admission", "result", "unknown"} {
		for _, reason := range []string{"deadline", "canceled", "mismatch", "unavailable", "other"} {
			row := "PHANTOWD_QEMU_NATIVE_WORKER_FAILURE phase=" + phase + " reason=" + reason + " scope=diagnostic-only\n"
			got := plannedFaultSubprocessDiagnosticQEMU(nil, errors.New("private"), row, "proof")
			want := "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=false child_failed=true proof_match=false scope=diagnostic-only\n" + row
			if got != want {
				t.Fatalf("lost producer classification %s/%s: %q", phase, reason, got)
			}
		}
	}
}

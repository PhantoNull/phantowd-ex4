//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// Diagnostics identify a fixed fixture boundary, never prove qualification or
// serialize an underlying error, credential, command, account or object path.
// An unknown label fails silent rather than permitting caller-controlled text.
func plannedFaultFailureDiagnosticQEMU(phase string, err error) string {
	if err == nil || !validPlannedFaultPhaseQEMU(phase) {
		return ""
	}
	output := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=%s deadline=%t review=%t scope=diagnostic-only\n", phase, errors.Is(err, context.DeadlineExceeded), errors.Is(err, runtimebundle.ErrReviewRequired))
	return output + plannedDataFailureDiagnosticQEMU(runtimebundle.ObserveNativeDataFailureQEMU(err))
}

func plannedDataFailureDiagnosticQEMU(data runtimebundle.NativeDataFailureObservationQEMU) string {
	if !data.Present {
		return ""
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_DATA_FAILURE operation=%s phase=%s reason=%s scope=diagnostic-only", data.Operation, data.Phase, data.Reason)
	if !validPlannedDataDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedDataDiagnosticQEMU(fields []string) bool {
	if len(fields) != 5 || fields[0] != "PHANTOWD_QEMU_DATA_FAILURE" || fields[4] != "scope=diagnostic-only" {
		return false
	}
	switch fields[1] {
	case "operation=rw-write", "operation=rw-read", "operation=ro-read", "operation=ro-write", "operation=escape", "operation=ungranted", "operation=unix-owner", "operation=kernel-ro", "operation=transfer", "operation=denial", "operation=final-daemon":
	default:
		return false
	}
	switch fields[2] {
	case "phase=pre-admission", "phase=execution", "phase=settlement", "phase=post-admission", "phase=result":
	default:
		return false
	}
	switch fields[3] {
	case "reason=deadline", "reason=canceled", "reason=mismatch", "reason=unavailable", "reason=other":
		return true
	default:
		return false
	}
}

func validPlannedFaultPhaseQEMU(phase string) bool {
	switch phase {
	case "construction", "storage", "identity-policy", "handoff", "configuration", "admission", "startup", "data", "supervision", "initial", "cover", "quarantine", "retention", "restoration", "review-close":
		return true
	default:
		return false
	}
}

// Child output remains untrusted and bounded by nativeFaultOutput. Relay only
// exact fixed-label diagnostic rows, once each; never relay raw errors or treat
// telemetry plus a valid marker as the exact successful child proof.
func plannedFaultSubprocessDiagnosticQEMU(ctxErr, runErr error, captured, proof string) string {
	if ctxErr == nil && runErr == nil && captured == proof {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE deadline=%t child_failed=%t proof_match=%t scope=diagnostic-only\n", errors.Is(ctxErr, context.DeadlineExceeded), runErr != nil, captured == proof)
	seen := make(map[string]bool)
	for _, line := range strings.Split(captured, "\n") {
		fields := strings.Split(line, " ")
		if validPlannedDataDiagnosticQEMU(fields) && !seen[line] {
			seen[line] = true
			output.WriteString(line)
			output.WriteByte('\n')
			continue
		}
		if len(fields) != 5 || fields[0] != "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE" || fields[4] != "scope=diagnostic-only" {
			continue
		}
		phase, present := strings.CutPrefix(fields[1], "phase=")
		if !present || !validPlannedFaultPhaseQEMU(phase) ||
			(fields[2] != "deadline=true" && fields[2] != "deadline=false") ||
			(fields[3] != "review=true" && fields[3] != "review=false") || seen[line] {
			continue
		}
		seen[line] = true
		output.WriteString(line)
		output.WriteByte('\n')
	}
	return output.String()
}

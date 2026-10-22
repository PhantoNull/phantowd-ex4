//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

// Diagnostics identify a fixed fixture boundary, never prove qualification or
// serialize an underlying error, credential, command, account or object path.
// An unknown label fails silent rather than permitting caller-controlled text.
func plannedFaultFailureDiagnosticQEMU(phase string, err error) string {
	if err == nil || !validPlannedFaultPhaseQEMU(phase) {
		return ""
	}
	output := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=%s deadline=%t review=%t scope=diagnostic-only\n", phase, errors.Is(err, context.DeadlineExceeded), errors.Is(err, runtimebundle.ErrReviewRequired))
	return output + plannedDataRefusalDiagnosticQEMU(err) + plannedExitFailureDiagnosticQEMU(err)
}

// Direct data and fault consumers share the same failure-only observations.
// Each observer returns only an immutable, typed snapshot; no work is retried.
func plannedDataRefusalDiagnosticQEMU(err error) string {
	if err == nil {
		return ""
	}
	return plannedAccessStageDiagnosticQEMU(smbexec.ObserveNativePlannedDataStageQEMU(err)) +
		plannedAccessContextDiagnosticQEMU(smbexec.ObserveNativePlannedDataContextQEMU(err)) +
		plannedAccessCostDiagnosticQEMU(smbexec.ObserveNativePlannedDataCostsQEMU(err)) +
		plannedDataFailureDiagnosticQEMU(runtimebundle.ObserveNativeDataFailureQEMU(err)) +
		plannedDataCostDiagnosticQEMU(runtimebundle.ObservePlannedDataCostsQEMU(err)) +
		plannedCheckCostDiagnosticQEMU(runtimebundle.ObservePlannedCheckCostsQEMU(err))
}

func plannedAccessContextDiagnosticQEMU(state string) string {
	row := "PHANTOWD_QEMU_PLANNED_ACCESS_CONTEXT state=" + state + " scope=diagnostic-only"
	if !validPlannedAccessContextDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedAccessContextDiagnosticQEMU(fields []string) bool {
	if len(fields) != 3 || fields[0] != "PHANTOWD_QEMU_PLANNED_ACCESS_CONTEXT" || fields[2] != "scope=diagnostic-only" {
		return false
	}
	switch fields[1] {
	case "state=live", "state=canceled", "state=deadline":
		return true
	default:
		return false
	}
}

func plannedAccessStageDiagnosticQEMU(stage string) string {
	row := "PHANTOWD_QEMU_PLANNED_ACCESS_FAILURE stage=" + stage + " scope=diagnostic-only"
	if !validPlannedAccessStageDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedAccessStageDiagnosticQEMU(fields []string) bool {
	if len(fields) != 3 || fields[0] != "PHANTOWD_QEMU_PLANNED_ACCESS_FAILURE" || fields[2] != "scope=diagnostic-only" {
		return false
	}
	switch fields[1] {
	case "stage=before-runtime", "stage=runtime", "stage=after-runtime":
		return true
	default:
		return false
	}
}

func plannedDataCostDiagnosticQEMU(c runtimebundle.PlannedDataCostObservationQEMU) string {
	if !c.Present {
		return ""
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_DATA_COSTS checks=%d check_ms=%d clients=%d client_ms=%d total_ms=%d scope=diagnostic-only", c.Checks, c.CheckMS, c.Clients, c.ClientMS, c.TotalMS)
	if !validPlannedDataCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedDataCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 7 || fields[0] != "PHANTOWD_QEMU_PLANNED_DATA_COSTS" || fields[6] != "scope=diagnostic-only" {
		return false
	}
	keys := [...]string{"checks=", "check_ms=", "clients=", "client_ms=", "total_ms="}
	var values [5]uint64
	for index, key := range keys {
		text, ok := strings.CutPrefix(fields[index+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[index] = value
	}
	return values[0] <= 13 && values[2] <= 6 && values[1] <= values[4] && values[3] <= values[4]-values[1] &&
		(values[0] != 0 || values[1] == 0) && (values[2] != 0 || values[3] == 0)
}

func plannedPhaseCostDiagnosticQEMU(startup, data, total int64) string {
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_PHASE_COSTS startup_ms=%d data_ms=%d total_ms=%d scope=diagnostic-only", startup, data, total)
	if !validPlannedPhaseCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedPhaseCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 5 || fields[0] != "PHANTOWD_QEMU_PLANNED_PHASE_COSTS" || fields[4] != "scope=diagnostic-only" {
		return false
	}
	keys := [...]string{"startup_ms=", "data_ms=", "total_ms="}
	var values [3]uint64
	for index, key := range keys {
		text, ok := strings.CutPrefix(fields[index+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[index] = value
	}
	return values[0] <= values[2] && values[1] <= values[2]-values[0]
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
		if (validPlannedAccessStageDiagnosticQEMU(fields) || validPlannedAccessContextDiagnosticQEMU(fields) || validPlannedAccessCostDiagnosticQEMU(fields) || validPlannedDataCostDiagnosticQEMU(fields) || validPlannedCheckCostDiagnosticQEMU(fields) || validPlannedPhaseCostDiagnosticQEMU(fields)) && !seen[line] {
			seen[line] = true
			output.WriteString(line)
			output.WriteByte('\n')
			continue
		}
		if validPlannedSourceCostDiagnosticQEMU(fields) && !seen[line] {
			seen[line] = true
			output.WriteString(line)
			output.WriteByte('\n')
			continue
		}
		if validPlannedExitDiagnosticQEMU(fields) && !seen[line] {
			seen[line] = true
			output.WriteString(line)
			output.WriteByte('\n')
			continue
		}
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

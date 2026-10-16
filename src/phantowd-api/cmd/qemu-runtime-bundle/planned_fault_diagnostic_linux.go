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
	return output + plannedDataFailureDiagnosticQEMU(runtimebundle.ObserveNativeDataFailureQEMU(err)) +
		plannedDataClockDiagnosticQEMU(runtimebundle.ObserveNativeDataClockQEMU(err)) +
		plannedServiceFailureDiagnosticQEMU(smbexec.ObserveNativePlannedFailureQEMU(err)) + plannedExitFailureDiagnosticQEMU(err)
}

func plannedServiceFailureDiagnosticQEMU(failure smbexec.NativePlannedFailureObservationQEMU) string {
	if !failure.Present {
		return ""
	}
	contextDone, deadlineReached := "unavailable", "unavailable"
	if failure.ContextPresent {
		contextDone = strconv.FormatBool(failure.ContextDone)
	}
	if failure.ContextPresent && failure.DeadlinePresent {
		deadlineReached = strconv.FormatBool(failure.DeadlineReached)
	}
	if (!failure.ContextPresent && (failure.ContextDone || failure.DeadlinePresent || failure.DeadlineReached)) || (!failure.DeadlinePresent && failure.DeadlineReached) {
		return ""
	}
	row := "PHANTOWD_QEMU_PLANNED_SERVICE_FAILURE boundary=" + failure.Boundary + " context_done=" + contextDone + " deadline_reached=" + deadlineReached + " scope=diagnostic-only"
	if !validPlannedServiceFailureDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedServiceFailureDiagnosticQEMU(fields []string) bool {
	if len(fields) != 5 || fields[0] != "PHANTOWD_QEMU_PLANNED_SERVICE_FAILURE" || fields[4] != "scope=diagnostic-only" {
		return false
	}
	if fields[2] != "context_done=true" && fields[2] != "context_done=false" && fields[2] != "context_done=unavailable" {
		return false
	}
	if fields[3] != "deadline_reached=true" && fields[3] != "deadline_reached=false" && fields[3] != "deadline_reached=unavailable" {
		return false
	}
	if fields[2] == "context_done=unavailable" && fields[3] != "deadline_reached=unavailable" {
		return false
	}
	switch fields[1] {
	case "boundary=verify-source-set", "boundary=verify-role", "boundary=verify-share-pins", "boundary=verify-owners", "boundary=verify-freshness", "boundary=verify-held-session", "boundary=verify-held-file", "boundary=data-admission", "boundary=data-state":
		return true
	case "boundary=held-file-admission", "boundary=held-file-state", "boundary=held-file-retain", "boundary=held-file-client", "boundary=held-file-observe":
		return true
	default:
		return false
	}
}

func plannedDataClockDiagnosticQEMU(c runtimebundle.NativeDataClockObservationQEMU) string {
	if !c.Present {
		return ""
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_DATA_CLOCK elapsed_ms=%d entered_remaining_ms=%d failed_remaining_ms=%d context_done=%t deadline_reached=%t scope=diagnostic-only", c.ElapsedMS, c.EnteredRemainingMS, c.FailedRemainingMS, c.ContextDone, c.DeadlineReached)
	if !validPlannedDataClockDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedDataClockDiagnosticQEMU(fields []string) bool {
	if len(fields) != 7 || fields[0] != "PHANTOWD_QEMU_PLANNED_DATA_CLOCK" || fields[6] != "scope=diagnostic-only" ||
		(fields[4] != "context_done=true" && fields[4] != "context_done=false") ||
		(fields[5] != "deadline_reached=true" && fields[5] != "deadline_reached=false") {
		return false
	}
	keys := [...]string{"elapsed_ms=", "entered_remaining_ms=", "failed_remaining_ms="}
	var values [3]uint64
	for index, key := range keys {
		text, ok := strings.CutPrefix(fields[index+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[index] = value
	}
	if values[2] > values[1] {
		return false
	}
	return fields[5] != "deadline_reached=true" || (values[2] == 0 && values[0] >= values[1])
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
		if validPlannedServiceFailureDiagnosticQEMU(fields) && !seen["service-boundary"] {
			seen["service-boundary"] = true
			output.WriteString(line)
			output.WriteByte('\n')
			continue
		}
		if validPlannedDataClockDiagnosticQEMU(fields) && !seen["data-clock"] {
			seen["data-clock"] = true
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

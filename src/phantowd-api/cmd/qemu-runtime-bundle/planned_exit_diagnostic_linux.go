//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Private fixture boundary only: preserve the refusal without serializing its
// text or accepting caller-selected paths, objects, commands or retry policy.
type plannedExitBoundaryFailureQEMU struct {
	phase string
	cause error
}

func (e *plannedExitBoundaryFailureQEMU) Error() string { return "planned exit qualification refused" }
func (e *plannedExitBoundaryFailureQEMU) Unwrap() error { return e.cause }

func validPlannedExitPhaseQEMU(phase string) bool {
	switch phase {
	case "initial", "first-scan", "exclusivity", "canceled-request", "request", "repeated-request", "quarantine",
		"stop-observation", "stop-witness", "capture-witness", "authority", "normal-stop-refusal",
		"nonrevival", "supervisor-refusal", "final-retention":
		return true
	default:
		return false
	}
}

func plannedExitFailureDiagnosticQEMU(err error) string {
	var boundary *plannedExitBoundaryFailureQEMU
	if !errors.As(err, &boundary) || boundary == nil || boundary.cause == nil || !validPlannedExitPhaseQEMU(boundary.phase) {
		return ""
	}
	return fmt.Sprintf("PHANTOWD_QEMU_PLANNED_EXIT_FAILURE phase=%s busy=%t scope=diagnostic-only\n", boundary.phase, errors.Is(err, processowner.ErrBusy))
}

func validPlannedExitDiagnosticQEMU(fields []string) bool {
	if len(fields) != 4 || fields[0] != "PHANTOWD_QEMU_PLANNED_EXIT_FAILURE" || fields[3] != "scope=diagnostic-only" ||
		(fields[2] != "busy=true" && fields[2] != "busy=false") {
		return false
	}
	phase, present := strings.CutPrefix(fields[1], "phase=")
	return present && validPlannedExitPhaseQEMU(phase)
}

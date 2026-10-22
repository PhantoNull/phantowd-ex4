//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

func plannedAccessCostDiagnosticQEMU(c smbexec.NativePlannedDataCostsObservationQEMU) string {
	if !c.Present {
		return ""
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_ACCESS_COSTS before_ms=%d runtime_ms=%d after_ms=%d total_ms=%d scope=diagnostic-only", c.BeforeMS, c.RuntimeMS, c.AfterMS, c.TotalMS)
	if !validPlannedAccessCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedAccessCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 6 || fields[0] != "PHANTOWD_QEMU_PLANNED_ACCESS_COSTS" || fields[5] != "scope=diagnostic-only" {
		return false
	}
	keys := [...]string{"before_ms=", "runtime_ms=", "after_ms=", "total_ms="}
	var values [4]uint64
	for i, key := range keys {
		text, ok := strings.CutPrefix(fields[i+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[i] = value
	}
	return values[0]+values[1]+values[2] <= values[3]
}

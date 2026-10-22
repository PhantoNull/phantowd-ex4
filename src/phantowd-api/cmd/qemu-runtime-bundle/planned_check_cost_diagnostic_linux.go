//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func plannedCheckCostDiagnosticQEMU(c runtimebundle.PlannedCheckCostObservationQEMU) string {
	if !c.Present || c.Checks < 1 || c.Checks > len(c.MS) {
		return ""
	}
	values := make([]string, c.Checks)
	for i, ms := range c.MS {
		if ms < 0 || ms > 180000 || (i >= c.Checks && ms != 0) {
			return ""
		}
		if i < c.Checks {
			values[i] = strconv.FormatInt(ms, 10)
		}
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_CHECK_COSTS checks=%d ms=%s scope=diagnostic-only", c.Checks, strings.Join(values, ","))
	if !validPlannedCheckCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedCheckCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 4 || fields[0] != "PHANTOWD_QEMU_PLANNED_CHECK_COSTS" || fields[3] != "scope=diagnostic-only" {
		return false
	}
	text, ok := strings.CutPrefix(fields[1], "checks=")
	count, err := strconv.ParseUint(text, 10, 8)
	if !ok || err != nil || count < 1 || count > 13 || strconv.FormatUint(count, 10) != text {
		return false
	}
	text, ok = strings.CutPrefix(fields[2], "ms=")
	values := strings.Split(text, ",")
	if !ok || len(values) != int(count) {
		return false
	}
	var total uint64
	for _, value := range values {
		ms, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(ms, 10) != value || ms > 180000 {
			return false
		}
		total += ms
	}
	return total <= 180000
}

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

func plannedRuntimeDataCostDiagnosticQEMU(c runtimebundle.PlannedDataCostQEMU) string {
	if !c.Present {
		return ""
	}
	const limit = int64(180_000_000_000)
	if c.ChecksNS < 0 || c.ChecksNS > limit || c.ClientsNS < 0 || c.ClientsNS > limit || c.RemainderNS < 0 || c.RemainderNS > limit ||
		c.ChecksNS+c.ClientsNS+c.RemainderNS > limit || (c.Checks == 0 && c.ChecksNS != 0) || (c.Clients == 0 && c.ClientsNS != 0) {
		return ""
	}
	row := fmt.Sprintf("PHANTOWD_QEMU_RUNTIME_COSTS checks=%d clients=%d checks_ms=%d clients_ms=%d remainder_ms=%d scope=diagnostic-only", c.Checks, c.Clients, c.ChecksNS/1_000_000, c.ClientsNS/1_000_000, c.RemainderNS/1_000_000)
	if !validPlannedRuntimeDataCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

func validPlannedRuntimeDataCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 7 || fields[0] != "PHANTOWD_QEMU_RUNTIME_COSTS" || fields[6] != "scope=diagnostic-only" {
		return false
	}
	keys := [...]string{"checks=", "clients=", "checks_ms=", "clients_ms=", "remainder_ms="}
	var values [5]uint64
	for i, key := range keys {
		text, ok := strings.CutPrefix(fields[i+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[i] = value
	}
	return values[0] <= 13 && values[1] <= 6 && values[2]+values[3]+values[4] <= 180000 &&
		(values[0] != 0 || values[2] == 0) && (values[1] != 0 || values[3] == 0)
}

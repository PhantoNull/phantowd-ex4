//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cumulative checkpoints describe this fixed fixture's elapsed work, not
// exclusive CPU time, successful effects, stop completion or qualification.
// They never change the existing contexts, action ordering or authority.
type plannedSourceCostsQEMU struct {
	steps uint8
	ms    [4]int64
	total int64
}

type plannedSourceCostClockQEMU struct {
	start time.Time
	costs plannedSourceCostsQEMU
	bad   bool
}

func (c *plannedSourceCostClockQEMU) mark() {
	if c.start.IsZero() || c.costs.steps >= 4 {
		c.bad = true
		return
	}
	c.costs.ms[c.costs.steps] = time.Since(c.start).Milliseconds()
	c.costs.steps++
}

func (c *plannedSourceCostClockQEMU) annotate(err error) error {
	if err == nil || c.bad || c.start.IsZero() {
		return err
	}
	costs := c.costs // No mutable clock or authority is retained in the error.
	costs.total = time.Since(c.start).Milliseconds()
	return &plannedSourceCostFailureQEMU{cause: err, costs: costs}
}

type plannedSourceCostFailureQEMU struct {
	cause error
	costs plannedSourceCostsQEMU
}

func (e *plannedSourceCostFailureQEMU) Error() string { return "planned source fault diagnostic" }
func (e *plannedSourceCostFailureQEMU) Unwrap() error { return e.cause }

func plannedSourceCostDiagnosticQEMU(err error) string {
	var observed *plannedSourceCostFailureQEMU
	if err == nil || !errors.As(err, &observed) || observed == nil || observed.cause == nil {
		return ""
	}
	c := observed.costs
	row := fmt.Sprintf("PHANTOWD_QEMU_PLANNED_SOURCE_COSTS steps=%d held_ms=%d observed_ms=%d first_scan_ms=%d covered_ms=%d total_ms=%d scope=diagnostic-only", c.steps, c.ms[0], c.ms[1], c.ms[2], c.ms[3], c.total)
	if !validPlannedSourceCostDiagnosticQEMU(strings.Split(row, " ")) {
		return ""
	}
	return row + "\n"
}

// Child output remains untrusted. Fixed keys/order, canonical bounded integers
// and monotonic reached checkpoints exclude raw strings and invented roles.
// No field is accepted as proof, permission or a historical syscall outcome.
func validPlannedSourceCostDiagnosticQEMU(fields []string) bool {
	if len(fields) != 8 || fields[0] != "PHANTOWD_QEMU_PLANNED_SOURCE_COSTS" || fields[7] != "scope=diagnostic-only" {
		return false
	}
	keys := [...]string{"steps=", "held_ms=", "observed_ms=", "first_scan_ms=", "covered_ms=", "total_ms="}
	var values [6]uint64
	for index, key := range keys {
		text, ok := strings.CutPrefix(fields[index+1], key)
		value, err := strconv.ParseUint(text, 10, 32)
		if !ok || err != nil || strconv.FormatUint(value, 10) != text || value > 180000 {
			return false
		}
		values[index] = value
	}
	if values[0] > 4 {
		return false
	}
	previous := uint64(0)
	for index, value := range values[1:5] {
		if uint64(index) >= values[0] {
			if value != 0 { // A checkpoint not reached cannot claim elapsed work.
				return false
			}
		} else {
			if value < previous {
				return false
			}
			previous = value
		}
	}
	return values[5] >= previous
}

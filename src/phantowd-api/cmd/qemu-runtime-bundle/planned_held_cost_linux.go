//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"fmt"
	"time"
)

// Cumulative wall costs inside this fixed fixture only. No replacement timer,
// command wrapper, callback, result classification or authority is introduced.
type plannedHeldCostClockQEMU struct {
	start, deadline time.Time
	marks           [4]int64
	steps           uint8
	invalid         bool
}

func startPlannedHeldCostQEMU(ctx context.Context) plannedHeldCostClockQEMU {
	if ctx == nil {
		return plannedHeldCostClockQEMU{}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return plannedHeldCostClockQEMU{}
	}
	return plannedHeldCostClockQEMU{start: time.Now(), deadline: deadline}
}

func (c *plannedHeldCostClockQEMU) mark() {
	if c.invalid || c.start.IsZero() || c.steps >= 4 {
		c.invalid = true
		return
	}
	elapsed := time.Since(c.start).Milliseconds()
	if elapsed < 0 || elapsed > 180000 || (c.steps > 0 && elapsed < c.marks[c.steps-1]) {
		c.invalid = true
		return
	}
	c.marks[c.steps] = elapsed
	c.steps++
}

func (c plannedHeldCostClockQEMU) row(ctx context.Context, result error) string {
	if ctx == nil || c.invalid || c.start.IsZero() || c.deadline.IsZero() || c.steps > 4 {
		return ""
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !deadline.Equal(c.deadline) {
		return ""
	}
	now := time.Now()
	total := now.Sub(c.start).Milliseconds()
	budget := c.deadline.Sub(c.start).Milliseconds()
	if budget < 0 {
		budget = 0
	}
	if total < 0 || total > 180000 || budget > 180000 {
		return ""
	}
	for i, value := range c.marks {
		if value < 0 || value > total || (i >= int(c.steps) && value != 0) || (i > 0 && i < int(c.steps) && value < c.marks[i-1]) {
			return ""
		}
	}
	stages := [...]string{"held-start", "live-observation", "supervision", "stopped-observation", "close"}
	return fmt.Sprintf("PHANTOWD_DIAG_HELD_COSTS stage=%s steps=%d budget_ms=%d after_start_ms=%d after_live_ms=%d after_supervision_ms=%d after_stopped_ms=%d total_ms=%d failed=%t context_done=%t deadline_reached=%t qualifying=false scope=qemu-only\n", stages[c.steps], c.steps, budget, c.marks[0], c.marks[1], c.marks[2], c.marks[3], total, result != nil, ctx.Err() != nil, !now.Before(c.deadline))
}

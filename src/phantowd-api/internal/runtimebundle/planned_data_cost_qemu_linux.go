//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"
	"time"
)

// PlannedDataCostQEMU partitions elapsed wall time, not CPU or authority.
// Checks includes result inspection before the last daemon check. Counts are
// completed timing boundaries, never proof that their commands succeeded.
type PlannedDataCostQEMU struct {
	Present                          bool
	ChecksNS, ClientsNS, RemainderNS int64
	Checks, Clients                  uint8
}

type plannedDataCostClockQEMU struct {
	start   time.Time
	last    time.Duration
	cost    PlannedDataCostQEMU
	invalid bool
}

func (c *plannedDataCostClockQEMU) mark(client bool) {
	if c.start.IsZero() || c.invalid {
		return
	}
	elapsed := time.Since(c.start)
	if elapsed < c.last || elapsed > 180*time.Second {
		c.invalid = true
		return
	}
	if client {
		c.cost.ClientsNS += int64(elapsed - c.last)
		c.cost.Clients++
	} else {
		c.cost.ChecksNS += int64(elapsed - c.last)
		c.cost.Checks++
	}
	c.last = elapsed
	if c.cost.Clients > 6 || c.cost.Checks > 13 {
		c.invalid = true
	}
}

func (c plannedDataCostClockQEMU) finish() PlannedDataCostQEMU {
	if c.start.IsZero() || c.invalid {
		return PlannedDataCostQEMU{}
	}
	elapsed := time.Since(c.start)
	if elapsed < c.last || elapsed > 180*time.Second {
		return PlannedDataCostQEMU{}
	}
	c.cost.Present = true
	c.cost.RemainderNS = int64(elapsed - c.last)
	return c.cost
}

func (c PlannedDataCostQEMU) valid() bool {
	const limit = int64(180 * time.Second)
	return c.Present && c.Checks <= 13 && c.Clients <= 6 &&
		c.ChecksNS >= 0 && c.ChecksNS <= limit && c.ClientsNS >= 0 && c.ClientsNS <= limit &&
		c.RemainderNS >= 0 && c.RemainderNS <= limit && c.ChecksNS+c.ClientsNS+c.RemainderNS <= limit &&
		(c.Checks != 0 || c.ChecksNS == 0) && (c.Clients != 0 || c.ClientsNS == 0)
}

// AnnotateFailureQEMU attaches only a copy to a refusal. Success and the first
// original diagnostic are unchanged; no clock, command or resource escapes.
func (c PlannedDataCostQEMU) AnnotateFailureQEMU(err error) error {
	if err == nil || !c.valid() || ObservePlannedDataCostQEMU(err).Present {
		return err
	}
	return &plannedDataCostErrorQEMU{cause: err, cost: c}
}

type plannedDataCostErrorQEMU struct {
	cause error
	cost  PlannedDataCostQEMU
}

func (*plannedDataCostErrorQEMU) Error() string { return "planned data cost diagnostic" }
func (e *plannedDataCostErrorQEMU) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func ObservePlannedDataCostQEMU(err error) PlannedDataCostQEMU {
	var timed *plannedDataCostErrorQEMU
	if !errors.As(err, &timed) || timed == nil || timed.cause == nil || !timed.cost.valid() {
		return PlannedDataCostQEMU{}
	}
	return timed.cost
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"time"
)

// Cumulative elapsed wall time only, not exclusive CPU time, admission or proof.
// The snapshot is made before quarantine; no context or mutable clock escapes.
type NativePlannedDataCostObservationQEMU struct {
	Present                              bool
	Steps                                uint8
	BudgetMS, BeforeMS, ProbeMS, TotalMS int64
}

type nativePlannedDataCostClockQEMU struct {
	start, deadline time.Time
	cost            NativePlannedDataCostObservationQEMU
	invalid         bool
}

func startNativePlannedDataCostQEMU(ctx context.Context) nativePlannedDataCostClockQEMU {
	if ctx == nil {
		return nativePlannedDataCostClockQEMU{}
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nativePlannedDataCostClockQEMU{}
	}
	start := time.Now()
	budget := deadline.Sub(start).Milliseconds()
	if budget < 0 {
		budget = 0
	}
	return nativePlannedDataCostClockQEMU{start: start, deadline: deadline,
		cost: NativePlannedDataCostObservationQEMU{Present: true, BudgetMS: budget}}
}

func (c *nativePlannedDataCostClockQEMU) mark() {
	if c.start.IsZero() || c.invalid || c.cost.Steps >= 2 {
		c.invalid = true
		return
	}
	elapsed := time.Since(c.start).Milliseconds()
	if c.cost.Steps == 0 {
		c.cost.BeforeMS = elapsed
	} else {
		c.cost.ProbeMS = elapsed
	}
	c.cost.Steps++
}

func (c nativePlannedDataCostClockQEMU) annotate(err error) error {
	if err == nil || c.invalid || c.start.IsZero() || c.deadline.IsZero() || ObserveNativePlannedDataCostQEMU(err).Present {
		return err
	}
	if !nativePlannedDataCostStageQEMU(err, c.cost.Steps) {
		return err
	}
	cost := c.cost
	cost.TotalMS = time.Since(c.start).Milliseconds()
	if !validNativePlannedDataCostQEMU(cost) {
		return err
	}
	return &nativePlannedDataCostFailureQEMU{cause: err, cost: cost}
}

func validNativePlannedDataCostQEMU(c NativePlannedDataCostObservationQEMU) bool {
	if !c.Present || c.Steps > 2 || c.BudgetMS < 0 || c.BudgetMS > 180000 ||
		c.BeforeMS < 0 || c.ProbeMS < 0 || c.TotalMS < 0 || c.TotalMS > 180000 {
		return false
	}
	if c.Steps == 0 {
		return c.BeforeMS == 0 && c.ProbeMS == 0
	}
	if c.BeforeMS > c.TotalMS {
		return false
	}
	if c.Steps == 1 {
		return c.ProbeMS == 0
	}
	return c.ProbeMS >= c.BeforeMS && c.ProbeMS <= c.TotalMS
}

type nativePlannedDataCostFailureQEMU struct {
	cause error
	cost  NativePlannedDataCostObservationQEMU
}

func (*nativePlannedDataCostFailureQEMU) Error() string { return "native planned data cost diagnostic" }
func (e *nativePlannedDataCostFailureQEMU) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func nativePlannedDataCostStageQEMU(err error, steps uint8) bool {
	stage := ObserveNativePlannedDataStageQEMU(err)
	return (stage == "before-runtime" && steps == 0) ||
		(stage == "runtime" && steps == 1) || (stage == "after-runtime" && steps == 2)
}

func ObserveNativePlannedDataCostQEMU(err error) NativePlannedDataCostObservationQEMU {
	var timed *nativePlannedDataCostFailureQEMU
	if !errors.As(err, &timed) || timed == nil || timed.cause == nil || !validNativePlannedDataCostQEMU(timed.cost) || !nativePlannedDataCostStageQEMU(timed.cause, timed.cost.Steps) {
		return NativePlannedDataCostObservationQEMU{}
	}
	return timed.cost
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"
	"time"
)

// Fixed fixture timing only: elapsed wall time, not CPU or an access proof.
// Counters include an attempted check/client that returns an error. There is
// no callback, context change, subprocess, retained authority or success output.
type plannedDataCostClockQEMU struct {
	start                 time.Time
	checks, clients       int
	checkTime, clientTime time.Duration
}

type PlannedDataCostObservationQEMU struct {
	Present                    bool
	Checks, Clients            int
	CheckMS, ClientMS, TotalMS int64
}

type plannedDataCostFailureQEMU struct {
	cause error
	costs PlannedDataCostObservationQEMU
}

func (e *plannedDataCostFailureQEMU) Error() string { return "planned data diagnostic" }
func (e *plannedDataCostFailureQEMU) Unwrap() error { return e.cause }

func (c *plannedDataCostClockQEMU) annotate(err error) error {
	if err == nil || c.start.IsZero() || c.checkTime < 0 || c.clientTime < 0 {
		return err
	}
	costs := PlannedDataCostObservationQEMU{Present: true, Checks: c.checks, Clients: c.clients,
		CheckMS: c.checkTime.Milliseconds(), ClientMS: c.clientTime.Milliseconds(), TotalMS: time.Since(c.start).Milliseconds()}
	if !validPlannedDataCostsQEMU(costs) {
		return err
	}
	return &plannedDataCostFailureQEMU{cause: err, costs: costs}
}

func validPlannedDataCostsQEMU(c PlannedDataCostObservationQEMU) bool {
	return c.Present && c.Checks >= 0 && c.Checks <= 13 && c.Clients >= 0 && c.Clients <= 6 &&
		c.CheckMS >= 0 && c.ClientMS >= 0 && c.TotalMS >= 0 && c.TotalMS <= 180000 &&
		c.CheckMS <= c.TotalMS && c.ClientMS <= c.TotalMS-c.CheckMS &&
		(c.Checks != 0 || c.CheckMS == 0) && (c.Clients != 0 || c.ClientMS == 0)
}

// Diagnostic-only, immutable copy from the first typed cost annotation. No
// admission, identity refresh, syscall, retry or error text is exposed.
func ObservePlannedDataCostsQEMU(err error) PlannedDataCostObservationQEMU {
	var failure *plannedDataCostFailureQEMU
	if !errors.As(err, &failure) || failure == nil || failure.cause == nil || !validPlannedDataCostsQEMU(failure.costs) {
		return PlannedDataCostObservationQEMU{}
	}
	return failure.costs
}

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
	checkSamples          [13]time.Duration
	samplesRecorded       int
}

type PlannedDataCostObservationQEMU struct {
	Present                    bool
	Checks, Clients            int
	CheckMS, ClientMS, TotalMS int64
}

type plannedDataCostFailureQEMU struct {
	cause  error
	costs  PlannedDataCostObservationQEMU
	checks PlannedCheckCostObservationQEMU
}

// Ordered elapsed times for the existing fixed checks, never CPU time or proof.
// Arrays are copied into the failure; no callback or retained mutable observer.
type PlannedCheckCostObservationQEMU struct {
	Present bool
	Checks  int
	MS      [13]int64
}

func (c *plannedDataCostClockQEMU) recordCheck(elapsed time.Duration) {
	index := c.checks
	c.checks++
	c.checkTime += elapsed
	if index >= 0 && index < len(c.checkSamples) && c.samplesRecorded == index && elapsed >= 0 {
		c.checkSamples[index] = elapsed
		c.samplesRecorded++
	}
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
	checks := PlannedCheckCostObservationQEMU{}
	if c.checks > 0 && c.samplesRecorded == c.checks {
		checks.Present, checks.Checks = true, c.checks
		for i := 0; i < c.checks; i++ {
			checks.MS[i] = c.checkSamples[i].Milliseconds()
		}
	}
	return &plannedDataCostFailureQEMU{cause: err, costs: costs, checks: checks}
}

func validPlannedCheckCostsQEMU(c PlannedCheckCostObservationQEMU, aggregate PlannedDataCostObservationQEMU) bool {
	if !c.Present || c.Checks < 1 || c.Checks > len(c.MS) || c.Checks != aggregate.Checks {
		return false
	}
	var sum int64
	for i, ms := range c.MS {
		if ms < 0 || ms > 180000 || (i >= c.Checks && ms != 0) {
			return false
		}
		sum += ms
	}
	// Each sample is rounded down independently. Do not attribute rounding
	// differences to missing work or accept a sequence detached from its sum.
	return sum <= aggregate.CheckMS && aggregate.CheckMS-sum < int64(c.Checks)
}

func ObservePlannedCheckCostsQEMU(err error) PlannedCheckCostObservationQEMU {
	var failure *plannedDataCostFailureQEMU
	if !errors.As(err, &failure) || failure == nil || failure.cause == nil ||
		!validPlannedDataCostsQEMU(failure.costs) || !validPlannedCheckCostsQEMU(failure.checks, failure.costs) {
		return PlannedCheckCostObservationQEMU{}
	}
	return failure.checks
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

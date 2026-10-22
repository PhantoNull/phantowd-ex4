//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"errors"
	"time"
)

// Fixed coordinator wall intervals, copied at refusal BEFORE quarantine. No
// context, callback, authority, successful result or CPU measurement is held.
type NativePlannedDataCostsObservationQEMU struct {
	Present                               bool
	BeforeMS, RuntimeMS, AfterMS, TotalMS int64
}

type nativePlannedAccessCostClockQEMU struct {
	start time.Time
	steps int
	at    [3]time.Duration
}

func (c *nativePlannedAccessCostClockQEMU) mark() {
	c.steps++
	if c.steps <= len(c.at) {
		c.at[c.steps-1] = time.Since(c.start)
	}
}

func (c *nativePlannedAccessCostClockQEMU) observe(stage string) NativePlannedDataCostsObservationQEMU {
	var steps int
	switch stage {
	case "before-runtime":
		steps = 1
	case "runtime":
		steps = 2
	case "after-runtime":
		steps = 3
	default:
		return NativePlannedDataCostsObservationQEMU{}
	}
	if c == nil || c.start.IsZero() || c.steps != steps {
		return NativePlannedDataCostsObservationQEMU{}
	}
	total := time.Since(c.start)
	if total < 0 || total > 180*time.Second {
		return NativePlannedDataCostsObservationQEMU{}
	}
	var previous time.Duration
	var ms [3]int64
	for i, at := range c.at {
		if i >= steps {
			if at != 0 {
				return NativePlannedDataCostsObservationQEMU{}
			}
			continue
		}
		if at < previous || at > total {
			return NativePlannedDataCostsObservationQEMU{}
		}
		ms[i], previous = (at - previous).Milliseconds(), at
	}
	costs := NativePlannedDataCostsObservationQEMU{Present: true, BeforeMS: ms[0], RuntimeMS: ms[1], AfterMS: ms[2], TotalMS: total.Milliseconds()}
	if !validNativePlannedDataCostsQEMU(costs, stage) {
		return NativePlannedDataCostsObservationQEMU{}
	}
	return costs
}

func validNativePlannedDataCostsQEMU(c NativePlannedDataCostsObservationQEMU, stage string) bool {
	if !c.Present || c.BeforeMS < 0 || c.RuntimeMS < 0 || c.AfterMS < 0 || c.TotalMS < 0 || c.TotalMS > 180000 ||
		c.BeforeMS > c.TotalMS || c.RuntimeMS > c.TotalMS-c.BeforeMS || c.AfterMS > c.TotalMS-c.BeforeMS-c.RuntimeMS {
		return false
	}
	switch stage {
	case "before-runtime":
		return c.RuntimeMS == 0 && c.AfterMS == 0
	case "runtime":
		return c.AfterMS == 0
	case "after-runtime":
		return true
	default:
		return false
	}
}

func ObserveNativePlannedDataCostsQEMU(err error) NativePlannedDataCostsObservationQEMU {
	stage := ObserveNativePlannedDataStageQEMU(err)
	var failure *nativePlannedDataFailureQEMU
	if stage == "" || !errors.As(err, &failure) || failure == nil || !validNativePlannedDataCostsQEMU(failure.costs, stage) {
		return NativePlannedDataCostsObservationQEMU{}
	}
	return failure.costs
}

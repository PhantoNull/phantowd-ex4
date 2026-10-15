//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"
)

// Existing fixture caps only. No product/worker/guest allowance is changed.
const (
	plannedStartupLimitQEMU     = 40 * time.Second
	plannedDataLimitQEMU        = 20 * time.Second
	plannedSupervisionLimitQEMU = 20 * time.Second
	plannedFaultLimitQEMU       = 90 * time.Second
)

type plannedPhaseQEMU uint8

const (
	plannedStartupQEMU plannedPhaseQEMU = iota
	plannedDataQEMU
	plannedSupervisionQEMU
)

var errPlannedPhaseQEMU = errors.New("planned fixture phase refused")

// Sequential, single-goroutine orchestration only; carries no service authority.
// A phase transition preserves the ORIGINAL parent, not a canceled phase or a
// fresh Background. The current phase must finish on time before transition.
type plannedPhaseClockQEMU struct {
	self        *plannedPhaseClockQEMU
	parent, ctx context.Context
	cancel      context.CancelFunc
	phase       plannedPhaseQEMU
	closed      bool
}

func newPlannedPhaseClockQEMU(parent context.Context) (*plannedPhaseClockQEMU, error) {
	if parent == nil {
		return nil, errPlannedPhaseQEMU
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, plannedStartupLimitQEMU)
	if err := nativeLivePhaseErrorQEMU(ctx); err != nil {
		cancel()
		return nil, err
	}
	c := &plannedPhaseClockQEMU{parent: parent, ctx: ctx, cancel: cancel}
	c.self = c
	return c, nil
}

func (c *plannedPhaseClockQEMU) Check() error {
	if c == nil || c.self != c || c.closed || c.ctx == nil || c.phase > plannedSupervisionQEMU {
		return errPlannedPhaseQEMU
	}
	return nativeLivePhaseErrorQEMU(c.ctx)
}

func (c *plannedPhaseClockQEMU) Advance(next plannedPhaseQEMU) error {
	if err := c.Check(); err != nil {
		return err
	}
	if c.phase >= plannedSupervisionQEMU || next != c.phase+1 {
		return errPlannedPhaseQEMU
	}
	limit := plannedDataLimitQEMU
	if next == plannedSupervisionQEMU {
		limit = plannedSupervisionLimitQEMU
	}
	ctx, cancel := context.WithTimeout(c.parent, limit)
	c.cancel()
	c.ctx, c.cancel, c.phase = ctx, cancel, next
	return c.Check()
}

func (c *plannedPhaseClockQEMU) Close() {
	if c == nil || c.self != c || c.closed {
		return
	}
	c.closed = true
	c.cancel()
}

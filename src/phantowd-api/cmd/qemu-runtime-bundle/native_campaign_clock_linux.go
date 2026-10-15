//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"
)

// Ordinary native fixture only, not product or worker/daemon policy. The host
// guard is checked against these seconds by the source contract tests.
const (
	nativeCampaignWorkSecondsQEMU       = 300
	nativeCampaignSettlementSecondsQEMU = 30
	nativeCampaignBootSecondsQEMU       = 30

	nativePreparationLimitQEMU = 20 * time.Second
	nativeEnrollmentLimitQEMU  = 60 * time.Second
	nativeBackendLimitQEMU     = 20 * time.Second
	nativeDaemonLimitQEMU      = 20 * time.Second
	nativeIdleLimitQEMU        = 20 * time.Second
	nativeClientsLimitQEMU     = 20 * time.Second
	nativeLiveLimitQEMU        = 45 * time.Second
	nativeFreshLoginLimitQEMU  = 15 * time.Second
	nativeDataLimitQEMU        = 35 * time.Second
)

// This clock carries no identity or execution authority. Settlement shares one
// absolute deadline, not a renewable grace per Close/Stop. It is independent of
// work cancellation so cleanup can still verify stop, retaining review on error.
type nativeCampaignClockQEMU struct {
	work, settlement             context.Context
	cancelWork, cancelSettlement context.CancelFunc
}

func newNativeCampaignClockQEMU(parent context.Context) (*nativeCampaignClockQEMU, error) {
	if parent == nil {
		return nil, errors.New("native campaign requires parent")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	work, cancel := context.WithTimeout(parent, nativeCampaignWorkSecondsQEMU*time.Second)
	if err := nativeLivePhaseErrorQEMU(work); err != nil {
		cancel()
		return nil, err
	}
	deadline, _ := work.Deadline()
	settlement, cancelSettlement := context.WithDeadline(context.WithoutCancel(parent), deadline.Add(nativeCampaignSettlementSecondsQEMU*time.Second))
	return &nativeCampaignClockQEMU{work: work, settlement: settlement, cancelWork: cancel, cancelSettlement: cancelSettlement}, nil
}

func (c *nativeCampaignClockQEMU) Close() {
	if c == nil {
		return
	}
	c.cancelWork()
	c.cancelSettlement()
}

func (c *nativeCampaignClockQEMU) Settle(operation func(context.Context) error) error {
	if c == nil || c.settlement == nil || operation == nil {
		return errors.New("native settlement unavailable")
	}
	if err := nativeLivePhaseErrorQEMU(c.settlement); err != nil {
		return err
	}
	return errors.Join(operation(c.settlement), nativeLivePhaseErrorQEMU(c.settlement))
}

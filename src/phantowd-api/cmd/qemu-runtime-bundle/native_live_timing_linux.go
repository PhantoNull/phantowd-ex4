//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type nativeLiveOperationQEMU uint8

const (
	nativeLiveClientsQEMU nativeLiveOperationQEMU = iota
	nativeLivePairObserveQEMU
	nativeLivePairVerifyQEMU
	nativeLiveRevokeQEMU
	nativeLiveOldConsumerQEMU
	nativeLiveSuccessorQEMU
	nativeLiveJournalQEMU
	nativeLivePeerQEMU
	nativeLiveChangedPairQEMU
	nativeLiveFreshLoginQEMU
)

// Fixed fixture telemetry only. No error text, account or process identifiers,
// commands or replacement backend enters the row. It is never readiness,
// permission, cancellation handling, recovery or a reason to retry an operation.
func nativeLiveTimingQEMU(op nativeLiveOperationQEMU, begin bool, phase, elapsed, remaining time.Duration,
	parentDone bool, operationErr error) string {
	labels := [...]string{"clients", "pair-observe", "pair-verify", "revoke",
		"old-consumer", "successor", "journal", "peer", "changed-pair", "fresh-login"}
	if int(op) >= len(labels) || phase < 0 || phase > 10*time.Minute || elapsed < 0 ||
		elapsed > phase || remaining < 0 || remaining > 10*time.Minute || (begin && (elapsed != 0 || operationErr != nil)) {
		return ""
	}
	state, cause := "end", "none"
	if begin {
		state = "begin"
	}
	if operationErr != nil {
		cause = "other"
		if errors.Is(operationErr, context.DeadlineExceeded) {
			cause = "deadline"
		} else if errors.Is(operationErr, context.Canceled) {
			cause = "canceled"
		}
	}
	return fmt.Sprintf("PHANTOWD_DIAG_NATIVE_LIVE operation=%s state=%s phase_ms=%d operation_ms=%d remaining_ms=%d parent_done=%t failed=%t cause=%s qualifying=false scope=qemu-only",
		labels[op], state, phase.Milliseconds(), elapsed.Milliseconds(), remaining.Milliseconds(), parentDone, operationErr != nil, cause)
}

func reportNativeLiveTimingQEMU(ctx context.Context, op nativeLiveOperationQEMU, begin bool, phaseStarted, operationStarted time.Time, err error) {
	if ctx == nil {
		return
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return
	}
	now := time.Now()
	remaining := deadline.Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	elapsed := now.Sub(operationStarted)
	if begin {
		elapsed = 0
	}
	if row := nativeLiveTimingQEMU(op, begin, now.Sub(phaseStarted), elapsed, remaining, ctx.Err() != nil, err); row != "" {
		fmt.Println(row)
	}
}

func beginNativeLiveTimingQEMU(ctx context.Context, op nativeLiveOperationQEMU, phaseStarted time.Time) time.Time {
	started := time.Now()
	reportNativeLiveTimingQEMU(ctx, op, true, phaseStarted, started, nil)
	return started
}

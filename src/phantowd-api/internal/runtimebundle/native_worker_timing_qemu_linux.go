//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"fmt"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Fixed-label fixture cost observations, never worker output or admission
// evidence. No caller-selected sink, command, identity or replacement context.
func nativeWorkerTimingQEMU(operation processowner.NativeSambaOperationQEMU, stage nativeWorkerStageQEMU,
	elapsed, remaining time.Duration, parentDone bool, operationErr error) string {
	operations := [...]string{"", "check", "list", "create", "password", "enable", "disable", "status", "revoke"}
	if operation == 0 || int(operation) >= len(operations) || stage > nativeWorkerPostAdmissionQEMU ||
		elapsed < 0 || elapsed > 10*time.Minute || remaining < 0 || remaining > 10*time.Minute {
		return ""
	}
	phase, reason := nativeWorkerFailureQEMU(stage, operationErr).labels()
	if operationErr == nil {
		reason = "none"
	}
	return fmt.Sprintf("PHANTOWD_DIAG_NATIVE_WORKER operation=%s phase=%s elapsed_ms=%d remaining_ms=%d parent_done=%t failed=%t cause=%s qualifying=false scope=qemu-only",
		operations[operation], phase, elapsed.Milliseconds(), remaining.Milliseconds(), parentDone, operationErr != nil, reason)
}

func reportNativeWorkerTimingQEMU(ctx context.Context, operation processowner.NativeSambaOperationQEMU,
	stage nativeWorkerStageQEMU, started time.Time, operationErr error) {
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
	if row := nativeWorkerTimingQEMU(operation, stage, now.Sub(started), remaining, ctx.Err() != nil, operationErr); row != "" {
		fmt.Println(row)
	}
}

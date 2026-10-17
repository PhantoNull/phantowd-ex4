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

// Bounded fixed-label diagnostics, never worker output or readiness/authority.
// Milliseconds are individually rounded down; use the underlying nanoseconds
// for exact partition accounting. Child CPU is not host or peer/server CPU.
func nativeCaptureCostQEMU(op processowner.NativeSambaOperationQEMU, cost processowner.NativeCaptureCostQEMU) string {
	labels := [...]string{"", "check", "list", "create", "password", "enable", "disable", "status", "revoke"}
	if op == 0 || int(op) >= len(labels) || !cost.Present ||
		(cost.Started && !cost.InputChecked) || (cost.WaitReturned && !cost.Started) || (cost.ChildReaped && !cost.WaitReturned) ||
		(!cost.InputChecked && (cost.LaunchNS != 0 || cost.WaitNS != 0 || cost.PostNS != 0)) ||
		(!cost.Started && (cost.WaitNS != 0 || cost.PostNS != 0)) || (!cost.WaitReturned && cost.PostNS != 0) ||
		(!cost.ChildReaped && (cost.ChildUserNS != 0 || cost.ChildSystemNS != 0)) {
		return ""
	}
	for _, value := range [...]int64{cost.InputNS, cost.LaunchNS, cost.WaitNS, cost.PostNS, cost.TotalNS, cost.ChildUserNS, cost.ChildSystemNS} {
		if value < 0 || value > int64(10*time.Minute) {
			return ""
		}
	}
	if cost.InputNS+cost.LaunchNS+cost.WaitNS+cost.PostNS != cost.TotalNS {
		return ""
	}
	const ms = int64(time.Millisecond)
	return fmt.Sprintf("PHANTOWD_DIAG_NATIVE_CAPTURE operation=%s input_checked=%t started=%t wait_returned=%t direct_child_reaped=%t input_ms=%d launch_ms=%d wait_ms=%d post_ms=%d total_ms=%d direct_child_user_ms=%d direct_child_system_ms=%d qualifying=false scope=qemu-only",
		labels[op], cost.InputChecked, cost.Started, cost.WaitReturned, cost.ChildReaped,
		cost.InputNS/ms, cost.LaunchNS/ms, cost.WaitNS/ms, cost.PostNS/ms, cost.TotalNS/ms, cost.ChildUserNS/ms, cost.ChildSystemNS/ms)
}

func reportNativeCaptureCostQEMU(ctx context.Context, op processowner.NativeSambaOperationQEMU, capture *processowner.CaptureOwner) {
	if ctx == nil || ctx.Value(nativeWorkerTimingContextKeyQEMU{}) != true || capture == nil {
		return
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return
	}
	// Capture has returned under the containing runtime's exclusive gate. Read
	// only the completed diagnostic even if its operation expired; this context
	// never performs execution, settlement, retry or admission on its behalf.
	cost, err := capture.NativeCaptureCostQEMU(context.Background())
	if err != nil {
		return
	}
	if row := nativeCaptureCostQEMU(op, cost); row != "" {
		fmt.Println(row)
	}
}

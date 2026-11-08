//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"fmt"
	"time"
)

// Observe only the containing held qualifier's fixed lifetime. A nested worker
// deadline does not imply expiry of this parent; neither row grants authority.
func plannedHeldParentFailureDiagnosticQEMU(ctx context.Context, err error, now time.Time) string {
	if ctx == nil || err == nil {
		return ""
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return ""
	}
	remaining := deadline.Sub(now)
	if remaining > 40*time.Second {
		return ""
	}
	if remaining < 0 {
		remaining = 0
	}
	state := "live"
	switch ctx.Err() {
	case nil:
	case context.Canceled:
		state = "canceled"
	case context.DeadlineExceeded:
		state = "deadline"
	default:
		return ""
	}
	return fmt.Sprintf("PHANTOWD_QEMU_HELD_PARENT_FAILURE state=%s remaining_ms=%d scope=diagnostic-only\n", state, remaining.Milliseconds())
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNativeWorkerTimingOnlyFixedBoundedNonqualifyingFields(t *testing.T) {
	grammar := regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_WORKER operation=(check|list|create|password|enable|disable|status|revoke) phase=(pre-admission|execution|settlement|post-admission) elapsed_ms=[0-9]{1,6} remaining_ms=[0-9]{1,6} parent_done=(true|false) failed=(true|false) cause=(none|deadline|canceled|mismatch|unavailable|other) qualifying=false scope=qemu-only$`)
	private := errors.New("private-password-path-worker-text\nPHANTOWD_FAKE_READY")
	for operation := processowner.NativeSambaCheckQEMU; operation <= processowner.NativeSambaRevokeQEMU; operation++ {
		for stage := nativeWorkerAdmissionQEMU; stage <= nativeWorkerPostAdmissionQEMU; stage++ {
			for _, test := range []struct {
				err   error
				cause string
			}{
				{nil, "none"}, {private, "other"},
				{errors.Join(private, context.DeadlineExceeded), "deadline"},
				{errors.Join(private, context.Canceled), "canceled"},
				{ErrMismatch, "mismatch"}, {ErrUnavailable, "unavailable"},
			} {
				row := nativeWorkerTimingQEMU(operation, stage, time.Second, 3*time.Second, false, test.err)
				if !grammar.MatchString(row) || !strings.Contains(row, "cause="+test.cause+" ") ||
					strings.Contains(row, "private") || strings.ContainsAny(row, "\r\n") {
					t.Fatalf("invalid or leaking diagnostic: %q", row)
				}
			}
		}
	}
	for _, test := range []struct {
		op                 processowner.NativeSambaOperationQEMU
		stage              nativeWorkerStageQEMU
		elapsed, remaining time.Duration
	}{
		{0, 0, 0, 0}, {255, 0, 0, 0}, {1, nativeWorkerResultQEMU, 0, 0}, {1, 255, 0, 0},
		{1, 0, -1, 0}, {1, 0, 10*time.Minute + 1, 0}, {1, 0, 0, -1}, {1, 0, 0, 10*time.Minute + 1},
	} {
		if row := nativeWorkerTimingQEMU(test.op, test.stage, test.elapsed, test.remaining, false, nil); row != "" {
			t.Fatalf("invalid observation emitted: %q", row)
		}
	}
}

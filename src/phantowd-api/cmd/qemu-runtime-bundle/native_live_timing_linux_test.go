//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNativeLiveTimingFixedBoundedNonqualifyingFields(t *testing.T) {
	labels := []string{"clients", "pair-observe", "pair-verify", "revoke", "old-consumer",
		"successor", "journal", "peer", "changed-pair", "fresh-login"}
	grammar := regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_LIVE operation=[a-z-]+ state=(begin|end) phase_ms=[0-9]{1,6} operation_ms=[0-9]{1,6} remaining_ms=[0-9]{1,6} parent_done=(true|false) failed=(true|false) cause=(none|deadline|canceled|other) qualifying=false scope=qemu-only$`)
	for op, label := range labels {
		row := nativeLiveTimingQEMU(nativeLiveOperationQEMU(op), true, time.Second, 0, 44*time.Second, false, nil)
		want := fmt.Sprintf("PHANTOWD_DIAG_NATIVE_LIVE operation=%s state=begin phase_ms=1000 operation_ms=0 remaining_ms=44000 parent_done=false failed=false cause=none qualifying=false scope=qemu-only", label)
		if row != want || !grammar.MatchString(row) {
			t.Fatalf("begin %d: %q", op, row)
		}
		for _, candidate := range []struct {
			err   error
			cause string
		}{
			{nil, "none"}, {errors.New("private-password-path-worker-text"), "other"},
			{fmt.Errorf("private wrapper: %w", context.DeadlineExceeded), "deadline"},
			{errors.Join(errors.New("private"), context.Canceled), "canceled"},
		} {
			row := nativeLiveTimingQEMU(nativeLiveOperationQEMU(op), false, 45*time.Second, time.Second, 0, true, candidate.err)
			if !grammar.MatchString(row) || !strings.Contains(row, "cause="+candidate.cause+" ") ||
				strings.Contains(row, "private") || strings.Contains(row, "password") {
				t.Fatalf("end %d: %q", op, row)
			}
		}
	}
	for _, candidate := range []struct {
		op                        nativeLiveOperationQEMU
		begin                     bool
		phase, elapsed, remaining time.Duration
		err                       error
	}{
		{255, false, time.Second, 0, 0, nil},
		{0, false, -1, 0, 0, nil},
		{0, false, 10*time.Minute + 1, 0, 0, nil},
		{0, false, time.Second, -1, 0, nil},
		{0, false, time.Second, 2 * time.Second, 0, nil},
		{0, false, time.Second, 0, -1, nil},
		{0, false, time.Second, 0, 10*time.Minute + 1, nil},
		{0, true, time.Second, time.Nanosecond, 0, nil},
		{0, true, time.Second, 0, 0, context.Canceled},
	} {
		if row := nativeLiveTimingQEMU(candidate.op, candidate.begin, candidate.phase, candidate.elapsed, candidate.remaining, false, candidate.err); row != "" {
			t.Fatalf("invalid row emitted: %q", row)
		}
	}
}

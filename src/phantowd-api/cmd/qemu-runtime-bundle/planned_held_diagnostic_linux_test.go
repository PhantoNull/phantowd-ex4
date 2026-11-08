//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHeldParentDiagnosticDistinguishesNestedDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	deadline, _ := parent.Deadline()
	now := deadline.Add(-17448 * time.Millisecond)
	cause := errors.Join(context.DeadlineExceeded, errors.New("private cause must not be logged"))
	const want = "PHANTOWD_QEMU_HELD_PARENT_FAILURE state=live remaining_ms=17448 scope=diagnostic-only\n"
	if got := plannedHeldParentFailureDiagnosticQEMU(parent, cause, now); got != want {
		t.Fatalf("nested worker expiry changed parent observation: %q", got)
	}
	if actual, _ := parent.Deadline(); actual != deadline || parent.Err() != nil || !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatal("diagnosis changed the original lifetime or cause")
	}
}

func TestHeldParentDiagnosticFailureOnlyAndBounded(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	deadline, _ := parent.Deadline()
	canceled, cancelChild := context.WithCancel(parent)
	cancelChild()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	expiredDeadline, _ := expired.Deadline()
	failure := errors.New("private error")
	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
		now  time.Time
		want string
	}{
		{"nil context", nil, failure, time.Now(), ""},
		{"success", parent, nil, deadline.Add(-time.Second), ""},
		{"unbounded", context.Background(), failure, time.Now(), ""},
		{"outside fixed scope", parent, failure, deadline.Add(-41 * time.Second), ""},
		{"canceled success", canceled, nil, deadline.Add(-time.Second), ""},
		{"canceled parent", canceled, failure, deadline.Add(-time.Second), "PHANTOWD_QEMU_HELD_PARENT_FAILURE state=canceled remaining_ms=1000 scope=diagnostic-only\n"},
		{"expired parent", expired, failure, expiredDeadline.Add(time.Second), "PHANTOWD_QEMU_HELD_PARENT_FAILURE state=deadline remaining_ms=0 scope=diagnostic-only\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := plannedHeldParentFailureDiagnosticQEMU(test.ctx, test.err, test.now); got != test.want {
				t.Fatalf("unexpected parent diagnostic: %q", got)
			}
		})
	}
}

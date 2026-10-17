//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "time"

// Fixed-size diagnostic storage, not a callback, execution input or authority.
// Only the guarded native QEMU constructor enables it. Ordinary captures keep
// a nil pointer: no clock calls, allocation, retained child or output changes.
type captureFixtureTiming struct {
	marks                  [4]time.Time
	end                    time.Time
	count                  int
	invalid, childReaped   bool
	childUser, childSystem time.Duration
}

func (t *captureFixtureTiming) begin() {
	if t != nil {
		*t = captureFixtureTiming{count: 1}
		t.marks[0] = time.Now()
	}
}

func (t *captureFixtureTiming) mark(index int) {
	if t == nil {
		return
	}
	if index != t.count || index <= 0 || index >= len(t.marks) || !t.end.IsZero() {
		t.invalid = true
		return
	}
	t.marks[index] = time.Now()
	t.count++
}

func (t *captureFixtureTiming) observeChild(process *managedProcess) {
	if t == nil || process == nil || process.command == nil || !process.exited() || process.command.ProcessState == nil {
		return
	}
	// The SAME original Wait notification is closed before ProcessState is read.
	// This is the original child's wait accounting, which on Linux may include
	// descendants it reaped; not group absence. No signal, Wait, retry or retained reference.
	t.childReaped = true
	t.childUser = process.command.ProcessState.UserTime()
	t.childSystem = process.command.ProcessState.SystemTime()
}

func (t *captureFixtureTiming) finish() {
	if t != nil {
		t.end = time.Now()
	}
}

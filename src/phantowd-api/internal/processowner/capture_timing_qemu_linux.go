//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"time"
)

// NativeCaptureCostQEMU is diagnostic-only. WaitReturned means the wait SELECT
// returned, possibly on cancellation; ChildReaped independently requires the
// original direct-child Wait completion. Neither flag proves group settlement.
// Post includes verification and any internal cancellation/stop work, not only
// hashing. CPU is the original child's kernel wait record (including descendants
// it reaped on Linux), not peer/server CPU, I/O wait or host-emulator cost.
type NativeCaptureCostQEMU struct {
	Present, InputChecked, Started, WaitReturned, ChildReaped bool
	InputNS, LaunchNS, WaitNS, PostNS, TotalNS                int64
	ChildUserNS, ChildSystemNS                                int64
}

func (c *CaptureOwner) NativeCaptureCostQEMU(ctx context.Context) (NativeCaptureCostQEMU, error) {
	if err := c.enter(ctx); err != nil {
		return NativeCaptureCostQEMU{}, err
	}
	defer func() { <-c.gate }()
	t := c.fixtureTiming
	if t == nil || t.invalid || t.count < 1 || t.count > len(t.marks) || t.end.IsZero() {
		return NativeCaptureCostQEMU{}, nil
	}
	const bound = 10 * time.Minute
	total := t.end.Sub(t.marks[0])
	if total < 0 || total > bound || t.childUser < 0 || t.childUser > bound || t.childSystem < 0 || t.childSystem > bound {
		return NativeCaptureCostQEMU{}, nil
	}
	var elapsed [4]int64
	for index := 0; index < t.count; index++ {
		end := t.end
		if index+1 < t.count {
			end = t.marks[index+1]
		}
		delta := end.Sub(t.marks[index])
		if delta < 0 || delta > total {
			return NativeCaptureCostQEMU{}, nil
		}
		elapsed[index] = delta.Nanoseconds()
	}
	if elapsed[0]+elapsed[1]+elapsed[2]+elapsed[3] != total.Nanoseconds() {
		return NativeCaptureCostQEMU{}, nil
	}
	if err := ctx.Err(); err != nil {
		return NativeCaptureCostQEMU{}, err
	}
	return NativeCaptureCostQEMU{
		Present: true, InputChecked: t.count >= 2, Started: t.count >= 3, WaitReturned: t.count >= 4, ChildReaped: t.childReaped,
		InputNS: elapsed[0], LaunchNS: elapsed[1], WaitNS: elapsed[2], PostNS: elapsed[3], TotalNS: total.Nanoseconds(),
		ChildUserNS: t.childUser.Nanoseconds(), ChildSystemNS: t.childSystem.Nanoseconds(),
	}, nil
}

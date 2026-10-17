//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Synthetic formatter inputs test grammar/privacy only, never child/runtime
// authority. Real capture timing is separately tested in processowner/QEMU.
func TestNativeCaptureCostFixedNonqualifyingFields(t *testing.T) {
	const ms = int64(time.Millisecond)
	valid := processowner.NativeCaptureCostQEMU{Present: true, InputChecked: true, Started: true, WaitReturned: true, ChildReaped: true,
		InputNS: ms, LaunchNS: 2 * ms, WaitNS: 3 * ms, PostNS: 4 * ms, TotalNS: 10 * ms, ChildUserNS: ms, ChildSystemNS: ms}
	row := nativeCaptureCostQEMU(processowner.NativeSambaStatusQEMU, valid)
	want := "PHANTOWD_DIAG_NATIVE_CAPTURE operation=status input_checked=true started=true wait_returned=true direct_child_reaped=true input_ms=1 launch_ms=2 wait_ms=3 post_ms=4 total_ms=10 direct_child_user_ms=1 direct_child_system_ms=1 qualifying=false scope=qemu-only"
	if row != want || strings.ContainsAny(row, "\r\n") {
		t.Fatal("diagnostic grammar changed", row)
	}
	for _, mutate := range []func(*processowner.NativeCaptureCostQEMU){
		func(c *processowner.NativeCaptureCostQEMU) { c.Present = false },
		func(c *processowner.NativeCaptureCostQEMU) { c.InputNS = -1 },
		func(c *processowner.NativeCaptureCostQEMU) { c.TotalNS++ },
		func(c *processowner.NativeCaptureCostQEMU) { c.TotalNS = int64(11 * time.Minute) },
		func(c *processowner.NativeCaptureCostQEMU) { c.ChildUserNS = -1 },
		func(c *processowner.NativeCaptureCostQEMU) { c.ChildSystemNS = int64(11 * time.Minute) },
		func(c *processowner.NativeCaptureCostQEMU) { c.ChildReaped = false },
		func(c *processowner.NativeCaptureCostQEMU) { c.WaitReturned = false },
		func(c *processowner.NativeCaptureCostQEMU) { c.Started = false },
		func(c *processowner.NativeCaptureCostQEMU) { c.InputChecked = false },
	} {
		changed := valid
		mutate(&changed)
		if row := nativeCaptureCostQEMU(processowner.NativeSambaStatusQEMU, changed); row != "" {
			t.Fatal("inconsistent diagnostic published", row)
		}
	}
	for _, op := range []processowner.NativeSambaOperationQEMU{0, 255} {
		if row := nativeCaptureCostQEMU(op, valid); row != "" {
			t.Fatal("unbounded operation label published", row)
		}
	}
}

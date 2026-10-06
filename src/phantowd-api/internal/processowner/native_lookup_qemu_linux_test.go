//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"testing"
)

func TestNativeLookupCaptureRefusesHostWithoutConsumingCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("native refusal only; mandatory ARMv5 fixture executes positive/late/partial-refusal cases")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	inputs := [4]*os.File{caller, caller, caller, caller}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		capture, err := NewNativeLookupCaptureQEMU(caller, caller, inputs)
		if capture != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired the guarded native lookup worker", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("native refusal consumed its caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("native refusal leaked descriptors", err)
	}
}

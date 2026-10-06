//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"testing"
)

func TestNativeCredentialCaptureRefusesHostAndPreservesCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal only; fixed ARMv5 fixture executes credential workers")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	config := [5]*os.File{caller, caller, caller, caller, caller}
	state := [7]*os.File{caller, caller, caller, caller, caller, caller, caller}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		capture, err := NewNativeSambaCaptureQEMU(caller, caller, config, state, NativeSambaListQEMU, "")
		if capture != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired a native credential worker", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("host refusal consumed the caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("host refusal leaked descriptors", err)
	}
}

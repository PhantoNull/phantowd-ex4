//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

func TestNativeCredentialRuntimeRefusesHostBeforeConsumingRoots(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host admission refusal; ARMv5 fixture qualifies original inputs")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		var plan *Plan
		runtime, err := plan.NewNativeSambaRuntimeQEMU(context.Background(), caller, caller, caller, fileserviceplan.SambaEnrollmentLookup{})
		if runtime != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired credential authority", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("runtime refusal consumed its caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("runtime refusal leaked descriptors", err)
	}
	if docs, err := SambaCredentialDocumentsQEMU(fileserviceplan.SambaEnrollmentLookup{}); docs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("zero native evidence supplied configuration", err)
	}
}

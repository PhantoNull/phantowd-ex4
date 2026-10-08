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
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestPlannedDataInputsRefuseMissingRuntimeWithoutConsumingCaller(t *testing.T) {
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []mountowner.ServiceShareDescriptorQEMU{{ShareID: "readonly", ReadOnly: true, File: caller}}
	var runtime *NativeSambaRuntimeQEMU
	for range 16 {
		if err := runtime.PreparePlannedDataInputsQEMU(context.Background(), fileserviceplan.SambaRoleCandidate{}, inputs); !errors.Is(err, ErrInvalid) {
			t.Fatal("missing runtime acquired planned inputs", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("refusal consumed the caller descriptor", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("planned input refusal leaked descriptors", err)
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestPlannedConfigurationStageRequiresContextRuntimeAndActualQEMU(t *testing.T) {
	if stage, err := stagePlannedConfigurationQEMU(nil, nil, fileserviceplan.SambaRoleCandidate{}); stage != nil || err == nil {
		t.Fatal("absent authorities staged files")
	}
	runtime := &runtimebundle.NativeSambaRuntimeQEMU{}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if stage, err := stagePlannedConfigurationQEMU(canceled, runtime, fileserviceplan.SambaRoleCandidate{}); stage != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled authority staged files", err)
	}
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal; actual guarded staging runs only in QEMU fixture")
	}
	if stage, err := stagePlannedConfigurationQEMU(context.Background(), runtime, fileserviceplan.SambaRoleCandidate{}); stage != nil || err == nil {
		t.Fatal("host acquired a disposable staging role")
	}
}

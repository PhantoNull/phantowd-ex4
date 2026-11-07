//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

func TestOrdinaryPlannedConstructionFailureIsLabeled(t *testing.T) {
	const root = "/run/phantowd-samba-code"
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Skip("requires absent disposable fixture root; never touch an existing fixture")
	}
	const child = "PHANTOWD_TEST_PLANNED_EMPTY_ROOT"
	if os.Getenv(child) == "1" {
		// The actual empty-root refusal returns before any directory, daemon,
		// mount or identity operation. Exercise its ordinary (fault-empty) defer.
		if err := nativePlannedServiceFixtureQEMU(nil, fileserviceplan.SambaEnrollmentLookup{}, "", nil, ""); err == nil {
			t.Fatal("missing fixture root accepted")
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestOrdinaryPlannedConstructionFailureIsLabeled$")
	command.Env = append(os.Environ(), child+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("refusal subprocess: %v: %s", err, output)
	}
	want := "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=construction deadline=false review=false scope=diagnostic-only\n"
	if strings.Count(string(output), want) != 1 || strings.Contains(string(output), root) || strings.Contains(string(output), "READY") {
		t.Fatalf("ordinary refusal lost its fixed phase or leaked inputs: %s", output)
	}
}

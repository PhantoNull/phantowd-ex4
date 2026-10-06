//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/stateunmountdiag"
)

func TestQEMUStateProcReaderObservesAndRedactsOwnerCWD(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	anchor := t.TempDir()
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore test working directory: %v", err)
		}
	})
	if err := os.Chdir(anchor); err != nil {
		t.Fatal(err)
	}

	line := stateunmountdiag.Capture("EBUSY", os.Getpid(), anchor, "/dev/qemu-state-test", qemuStateProcReader{})
	const marker = "PHANTOWD_STATE_UNMOUNT_DIAG "
	if !strings.HasPrefix(line, marker) {
		t.Fatalf("missing diagnostic marker: %q", line)
	}
	var result struct {
		Processes []struct {
			PID int `json:"pid"`
		} `json:"processes"`
		PathReferences []struct {
			PID  int    `json:"pid"`
			Kind string `json:"kind"`
		} `json:"path_references"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &result); err != nil {
		t.Fatal(err)
	}
	ownerPID := os.Getpid()
	ownerFound := false
	for _, process := range result.Processes {
		ownerFound = ownerFound || process.PID == ownerPID
	}
	if !ownerFound {
		t.Fatalf("proc collector omitted the owner: %+v", result)
	}
	for _, reference := range result.PathReferences {
		if reference.PID == ownerPID && reference.Kind == "cwd-anchor" {
			if strings.Contains(line, anchor) {
				t.Fatalf("diagnostic leaked the fixed test path: %s", line)
			}
			return
		}
	}
	t.Fatalf("proc collector did not classify owner cwd: %s", line)
}

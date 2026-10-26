//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"testing"
)

func TestNASPolicyMainProcessRefusesHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("actual ARM proof runs in guarded guest")
	}
	if exerciseQEMUNASPolicyMainProcess() == nil {
		t.Fatal("main-process fixture admitted host")
	}
}

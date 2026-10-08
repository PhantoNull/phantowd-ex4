//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"testing"
)

func TestPlannedSourceFaultRefusesHostBeforeAnyMutation(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("the positive fixture requires a guarded disposable guest")
	}
	if err := nativePlannedSourceFaultQEMU(); err == nil {
		t.Fatal("non-ARM host admitted fixed mount fault")
	}
}

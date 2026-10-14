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
	for name, operation := range map[string]func() error{
		"idle-session":  nativePlannedSourceFaultQEMU,
		"original-file": nativePlannedFileSourceFaultQEMU,
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("non-ARM host admitted fixed mount fault")
			}
		})
	}
}

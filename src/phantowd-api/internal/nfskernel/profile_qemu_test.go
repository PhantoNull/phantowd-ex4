//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel_test

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

func TestProfileQEMURejectsForeignOrIncompleteKernelState(t *testing.T) {
	for _, state := range []struct {
		threads, ports string
		running        bool
	}{{"0\n", "", false}, {"2\n", "tcp 2049\n", true}} {
		if nfskernel.ValidateProfileQEMU([]byte(state.threads), []byte("+3\n"), []byte(state.ports), state.running) != nil {
			t.Fatal("exact disposable profile refused")
		}
		for _, version := range []string{"", "+3", "+3\n+4\n", "+3\n\n", "-3\n"} {
			if nfskernel.ValidateProfileQEMU([]byte(state.threads), []byte(version), []byte(state.ports), state.running) == nil {
				t.Fatal("incomplete or foreign version accepted")
			}
		}
		if nfskernel.ValidateProfileQEMU([]byte(state.threads), []byte("+3\n"), []byte(state.ports), !state.running) == nil {
			t.Fatal("opposite lifecycle profile accepted")
		}
	}
}

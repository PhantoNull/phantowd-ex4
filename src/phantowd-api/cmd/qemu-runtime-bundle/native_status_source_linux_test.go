//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestNativeStatusSourceDiagnosticFlagIsExplicitAndUnique(t *testing.T) {
	const flag = "phantowd_samba_status_source_diagnostic"
	for _, test := range []struct {
		line             string
		enabled, refused bool
	}{
		{"console=ttyAMA0", false, false},
		{"console=ttyAMA0 " + flag + "=1", true, false},
		{flag, false, true}, {flag + "=0", false, true},
		{flag + "=2", false, true}, {flag + "=1 " + flag + "=1", false, true},
		{flag + "=1 " + flag + "=0", false, true},
	} {
		got, err := nativeStatusSourceDiagnosticFlagQEMU([]byte(test.line))
		if got != test.enabled || (err != nil) != test.refused {
			t.Fatal("diagnostic flag ambiguity", test.line, got, err)
		}
	}
}

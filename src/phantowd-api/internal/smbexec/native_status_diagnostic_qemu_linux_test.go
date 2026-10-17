//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import "testing"

func TestEmptyNativeStatusDiagnosticReusesCompleteDecoder(t *testing.T) {
	for _, test := range []struct {
		input string
		empty bool
	}{
		{`{"version":"4.22.11","sessions":{}}`, true},
		{string(testSMBStatusJSON(true)), false},
		{`{"version":"4.22.11","sessions":null}`, false},
		{`{"version":"4.22.11","sessions":{},"sessions":{}}`, false},
		// Version/provenance is NOT supplied by the existing JSON decoder.
		{`{"sessions":{}}`, true}, {`{`, false},
	} {
		if got := EmptyNativeStatusDiagnosticQEMU([]byte(test.input)); got != test.empty {
			t.Fatal("diagnostic bypassed original bounded status decoder", got)
		}
	}
}

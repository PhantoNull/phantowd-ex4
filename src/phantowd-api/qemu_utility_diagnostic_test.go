// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"strings"
	"testing"
)

func TestQEMUUtilityDiagnosticIsBoundedAndSingleLine(t *testing.T) {
	var diagnostic qemuUtilityDiagnostic
	input := []byte(strings.Repeat("x", maxQEMUUtilityDiagnosticBytes+32))
	if written, err := diagnostic.Write(input); err != nil || written != len(input) {
		t.Fatalf("diagnostic writer did not consume subprocess output: written=%d err=%v", written, err)
	}
	if len(diagnostic.data) != maxQEMUUtilityDiagnosticBytes {
		t.Fatalf("diagnostic exceeded its fixed bound: %d bytes", len(diagnostic.data))
	}
	if got := diagnostic.String(); len(got) != maxQEMUUtilityDiagnosticBytes+len(" [truncated]") ||
		!strings.HasSuffix(got, " [truncated]") || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("diagnostic was not bounded, marked and single-line: %q", got)
	}
}

func TestQEMUUtilityDiagnosticNormalizesWhitespace(t *testing.T) {
	var diagnostic qemuUtilityDiagnostic
	if _, err := diagnostic.Write([]byte("mdadm: device busy\n  refusing to proceed\n")); err != nil {
		t.Fatal(err)
	}
	if got, want := diagnostic.String(), "mdadm: device busy refusing to proceed"; got != want {
		t.Fatalf("unexpected diagnostic normalization: got %q, want %q", got, want)
	}
}

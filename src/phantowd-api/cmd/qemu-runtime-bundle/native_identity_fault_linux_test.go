//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"io"
	"strings"
	"testing"
)

func TestNativeFaultOutputBoundCannotBeBypassedByCopy(t *testing.T) {
	var output nativeFaultOutput
	if _, ok := any(&output).(io.ReaderFrom); ok {
		t.Fatal("io.Copy can bypass the bound")
	}
	if _, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 1025))); err == nil || output.String() != "" {
		t.Fatal("oversized child evidence retained")
	}
	if _, err := io.Copy(&output, strings.NewReader(nativeFaultChildProof)); err != nil || output.String() != nativeFaultChildProof {
		t.Fatal("bounded child evidence refused", err)
	}
}

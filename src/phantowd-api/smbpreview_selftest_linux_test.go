//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"
	"strings"
	"testing"
)

func TestQEMUSMBPreviewIsExplicitlyNonClustered(t *testing.T) {
	if strings.Count(qemuSMBPreviewGlobals, "\n    clustering = no\n") != 1 {
		t.Fatal("standalone synthetic profile must explicitly disable clustering")
	}
}

func TestQEMUSMBPreview(t *testing.T) {
	if _, err := os.Stat("/usr/bin/testparm"); err != nil {
		t.Skip("host Samba parser unavailable; ARMv5 QEMU must execute this probe")
	}
	if err := exerciseQEMUSMBPreview(); err != nil {
		t.Fatal(err)
	}
}

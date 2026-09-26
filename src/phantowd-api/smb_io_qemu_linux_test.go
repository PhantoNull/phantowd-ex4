//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestQEMUSMBEffectiveFixture(t *testing.T) {
	p, err := qemuSMBPolicy()
	if err != nil || len(p.Shares) != 2 {
		t.Fatal("fixture policy", err)
	}
	for _, expected := range []string{"[PolicyShare]", "[UnixDenied]", "valid users = qpreader qpwriter", "read list = qpreader", "write list = qpwriter", "follow symlinks = no"} {
		if !strings.Contains(p.Sections, expected) {
			t.Fatal("missing fixture rule", expected)
		}
	}
	if strings.Contains(p.Sections, "qpoutsider") {
		t.Fatal("outsider granted access")
	}
	if runtime.GOARCH != "arm" {
		if err := runQEMUSMBTest(); err == nil {
			t.Fatal("host mutation guard failed")
		}
	}
	for _, address := range []string{"0100007F:05A5", "00000000:05A5", "0100000A:05A5", "00000000000000000000000000000000:05A5", "00000000000000000000000001000000:05A5"} {
		err := checkSMBFixtureListeners("0: " + address + " 00000000:0000 0A")
		if (err == nil) != (address == "0100007F:05A5") {
			t.Fatal("listener boundary", address, err)
		}
	}
}

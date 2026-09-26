//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"
	"runtime"
	"testing"
)

func TestQEMUStatePersistence(t *testing.T) {
	if err := runQEMUStateTest("unknown"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if runtime.GOARCH != "arm" {
		for _, phase := range []string{"unknown", "seed", "verify"} {
			if err := exerciseQEMUSMBReboot(phase); err == nil {
				t.Fatal("SMB reboot host mutation guard failed")
			}
		}
		if err := runQEMUStateTest("seed"); err == nil {
			t.Fatal("host accepted as QEMU target")
		}
	}
	dir := t.TempDir()
	if err := exerciseQEMUStatePersistence(dir, "verify"); err == nil {
		t.Fatal("missing state accepted")
	}
	if err := exerciseQEMUStatePersistence(dir, "unknown"); err == nil {
		t.Fatal("unknown scenario accepted")
	}
	for _, phase := range []string{"seed", "verify"} {
		if err := exerciseQEMUStatePersistence(dir, phase); err != nil {
			t.Fatal(phase, err)
		}
	}
	if err := exerciseQEMUStatePersistence(dir, "seed"); err == nil {
		t.Fatal("existing fixture state overwritten")
	}
	for _, path := range []string{dir + "/good/shares.json", dir + "/corrupt/shares.json", dir + "/corrupt/.shares.pending"} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("unexpected state permissions", path, err)
		}
	}
}

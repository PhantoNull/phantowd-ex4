//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import "testing"

func TestNativeMountedRosterRefusesHostAndMissingObserver(t *testing.T) {
	if err := WithQEMUNativeMountedSet(nil); err == nil {
		t.Fatal("missing observer admitted")
	}
	called := false
	if err := WithQEMUNativeMountedSet(func(*MountedVolumeSet) error { called = true; return nil }); err == nil || called {
		t.Fatal("host constructed a QEMU native mounted roster")
	}
}

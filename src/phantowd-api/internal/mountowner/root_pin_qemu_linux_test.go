//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import "testing"

func TestQEMUMountedLossRefusesNonFixtureInput(t *testing.T) {
	for _, source := range []string{"", "/", "/dev/sda", "/tmp/untrusted"} {
		called := false
		err := WithQEMUMountedSetLoss(source, func(*MountedVolumeSet, func() error, func() error) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatal("nonfixture source reached injection", source, err)
		}
	}
	if err := WithQEMUMountedSetLoss("", nil); err == nil {
		t.Fatal("nil observer admitted")
	}
}

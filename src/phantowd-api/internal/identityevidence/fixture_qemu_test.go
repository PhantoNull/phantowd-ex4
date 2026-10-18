//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityevidence

import "testing"

func TestMemoryOnlyGuestFixture(t *testing.T) {
	if err := RunQEMUFixture(); err != nil {
		t.Fatal(err)
	}
}

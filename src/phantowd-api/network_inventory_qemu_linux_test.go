//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUNetworkInventory(t *testing.T) {
	if err := exerciseQEMUNetworkInventory(); err != nil {
		t.Fatal(err)
	}
}

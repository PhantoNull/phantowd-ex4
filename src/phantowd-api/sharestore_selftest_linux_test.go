//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUShareStore(t *testing.T) {
	if err := exerciseQEMUShareStore(); err != nil {
		t.Fatal(err)
	}
}

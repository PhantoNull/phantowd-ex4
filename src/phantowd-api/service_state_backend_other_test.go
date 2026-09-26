//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestNonDevelopmentServiceStateRefused(t *testing.T) {
	backend, closeState, err := openDevelopmentServiceState("")
	if backend != nil || err != nil || closeState == nil {
		t.Fatal("disabled backend failed")
	}
	if err := closeState(); err != nil {
		t.Fatal(err)
	}
	if backend, closeState, err := openDevelopmentServiceState(t.TempDir()); backend != nil || closeState != nil || err == nil {
		t.Fatal("non-development backend enabled")
	}
}

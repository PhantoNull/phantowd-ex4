//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"testing"
)

func TestLoaderObserverRefusesNonARMHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive ARM proof requires disposable isolated guest")
	}
	if err := observeLoader(); err == nil {
		t.Fatal("loader observer admitted non-ARM host")
	}
}

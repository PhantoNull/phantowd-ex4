//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestNFSSourceMountedFixtureRefusesOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive fixture requires its dedicated disposable ARM guest")
	}
	called := false
	for _, ctx := range []context.Context{nil, context.Background()} {
		err := mountowner.WithQEMUNFSSourceMountedSet(ctx, func(*mountowner.MountedVolumeSet) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("ordinary host entered source mount fixture")
		}
	}
}

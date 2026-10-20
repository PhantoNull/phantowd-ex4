//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSSourceServerRefusesInvalidOriginalLifetime(t *testing.T) {
	for _, source := range []*runtimebundle.NFSSourceAccessQEMU{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if source.StartServerFixtureQEMU(ctx) == nil || source.CheckServerFixtureQEMU(ctx) == nil ||
				source.ExerciseServerIOFixtureQEMU(ctx) == nil || source.StopServerFixtureQEMU(ctx) == nil {
				t.Fatal("invalid source server admitted an operation")
			}
		}
	}
}

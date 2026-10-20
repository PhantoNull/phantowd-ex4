//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestSourceRuntimeAccessRefusesInvalidHandles(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.RunAccessFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source/input join started NFS access")
		}
	}
}

func TestSourceRuntimeLossProbeRefusesInvalidHandles(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.ProbeSourceLossFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source/input join accepted a live-loss proof")
		}
	}
}

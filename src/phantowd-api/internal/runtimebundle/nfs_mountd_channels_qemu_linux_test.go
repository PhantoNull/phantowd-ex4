//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSMountdChannelsRefuseHostAndInvalidHandles(t *testing.T) {
	if runtime.GOARCH != "arm" {
		value, err := runtimebundle.NewNFSMountdChannelsQEMU(context.Background())
		if value != nil || !errors.Is(err, runtimebundle.ErrInvalid) {
			t.Fatal("ordinary host admitted to kernel channel collection", err)
		}
	}
	for _, value := range []*runtimebundle.NFSMountdChannelsQEMU{nil, {}} {
		if value.Check(context.Background()) == nil || value.Close() == nil {
			t.Fatal("invalid channel lifetime accepted")
		}
	}
}

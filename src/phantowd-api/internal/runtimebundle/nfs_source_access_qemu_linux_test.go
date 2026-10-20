//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSInputsSourceAccessRefusesMissingOriginalLease(t *testing.T) {
	for _, lease := range []*runtimebundle.NFSInputLeaseQEMU{nil, {}} {
		if value, err := runtimebundle.NewNFSSourceAccessQEMU(context.Background(), lease, [4]*os.File{}); value != nil || err == nil {
			t.Fatal("missing original lease admitted")
		}
	}
}

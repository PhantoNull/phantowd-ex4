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

func TestNFSInputsSourceLossRefusesMissingOriginalLease(t *testing.T) {
	for _, lease := range []*runtimebundle.NFSInputLeaseQEMU{nil, {}} {
		if value, err := runtimebundle.NewNFSSourceLossAccessQEMU(context.Background(), lease, [4]*os.File{}); value != nil || err == nil {
			t.Fatal("missing original lease admitted a source-loss consumer")
		}
		if value, err := runtimebundle.NewNFSSourceDaemonLossAccessQEMU(context.Background(), lease, [4]*os.File{}); value != nil || err == nil {
			t.Fatal("missing original lease admitted a combined-fault consumer")
		}
	}
	for _, value := range []*runtimebundle.NFSSourceAccessQEMU{nil, {}} {
		if value.VerifySourceLossRetainedQEMU(context.Background()) == nil {
			t.Fatal("invalid consumer accepted a retained-live-loss proof")
		}
		if value.InjectSourceMountdExitFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid consumer interrupted mountd")
		}
	}
}

func TestNFSInputsSourceWithdrawalRefusesInvalidAuthority(t *testing.T) {
	for _, value := range []*runtimebundle.NFSSourceAccessQEMU{nil, {}} {
		if value.WithdrawSourceLossFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid consumer admitted cleanup after source loss")
		}
	}
}

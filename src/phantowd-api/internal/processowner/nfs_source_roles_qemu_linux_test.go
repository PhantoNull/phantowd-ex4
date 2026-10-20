//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSSourceRolesRefuseOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive proof requires the dedicated source guest")
	}
	if value, err := processowner.NewNFSSourceMountdPinnedQEMU(processowner.MemberSpec{}, nil, [4]*os.File{}, [4]*os.File{}, [6]*os.File{}); value != nil || err == nil {
		t.Fatal("ordinary host acquired source mountd role")
	}
	for _, role := range []processowner.NFSSourceExportOperationQEMU{processowner.NFSSourceActivateQEMU, processowner.NFSSourceWithdrawQEMU, processowner.NFSSourceFlushQEMU, "invalid"} {
		if value, err := processowner.NewNFSSourceExportCaptureQEMU(role, nil, nil, [4]*os.File{}, [10]*os.File{}); value != nil || err == nil {
			t.Fatal("ordinary host acquired export-control role")
		}
	}
}

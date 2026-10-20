//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner_test

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSTableCaptureRefusesOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive disposable ARM guard is qualified by the dedicated guest")
	}
	owner, err := processowner.NewNFSTableCaptureQEMU(nil, nil, [4]*os.File{})
	if owner != nil || !errors.Is(err, processowner.ErrInvalid) {
		t.Fatal("ordinary host gained the fixed NFS fixture", err)
	}
}

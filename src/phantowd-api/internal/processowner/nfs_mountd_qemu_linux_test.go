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

func TestNFSMountdRefusesOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive proof belongs to the dedicated guest")
	}
	owner, err := processowner.NewNFSMountdPinnedQEMU(processowner.MemberSpec{}, nil, [4]*os.File{}, [4]*os.File{})
	if owner != nil || !errors.Is(err, processowner.ErrInvalid) {
		t.Fatal("ordinary host admitted to mountd fixture", err)
	}
}

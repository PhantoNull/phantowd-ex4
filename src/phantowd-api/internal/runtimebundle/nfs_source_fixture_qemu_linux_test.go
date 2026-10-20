//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSInputsSourcePairRefusesOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive construction requires the dedicated disposable source guest")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		pair, err := runtimebundle.PrepareNFSSourceInputPairQEMU(ctx, nil, fileserviceplan.NFSv3Candidate{})
		if err == nil || pair[0] != nil || pair[1] != nil {
			t.Fatal("ordinary host obtained prepared source inputs")
		}
	}
}

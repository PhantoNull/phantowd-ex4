//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestKernelSocketFixtureRequiresUnmixedCodeProfile(t *testing.T) {
	base := "console=ttyAMA0 phantowd_nfs_code_fixture=1 quiet"
	if !kernelSocketCommandQEMU([]byte(base)) {
		t.Fatal("exact code profile refused")
	}
	for _, invalid := range []string{"", "quiet", base + "\x00", strings.Repeat("x", 4097),
		base + " phantowd_nfs_code_fixture=1", strings.ReplaceAll(base, "=1", "=0"),
		base + " phantowd_nfs_source_fixture=1", base + " phantowd_nfs_future=0",
		base + " phantowd_nfs_source_owner_kernel_construct_refusal_fixture=1"} {
		if kernelSocketCommandQEMU([]byte(invalid)) {
			t.Fatal("mixed/invalid code profile admitted")
		}
	}
	if runtime.GOARCH != "arm" {
		before, err := sourceFDCount()
		if err != nil {
			t.Fatal(err)
		}
		for _, ctx := range []context.Context{nil, context.Background()} {
			if runKernelSocketRefusalQEMU(ctx, []byte(base)) == nil {
				t.Fatal("ordinary host admitted to fixture")
			}
		}
		if after, err := sourceFDCount(); err != nil || after != before || kernelSocketFixtureRetained.controller != nil || kernelSocketFixtureRetained.foreign != nil {
			t.Fatal("host refusal acquired a resource", err)
		}
	}
}

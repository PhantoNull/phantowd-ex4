//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--loader-observer" {
		if observeLoader() != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_LOADER_CHILD_FAILED")
			os.Exit(1)
		}
		return
	}
	sourceFixture := len(os.Args) == 2 && os.Args[1] == "--source-binding"
	sourceLoss := len(os.Args) == 2 && os.Args[1] == "--source-loss"
	if (!sourceFixture && !sourceLoss && len(os.Args) != 1) || runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		os.Exit(1)
	}
	file, err := os.Open("/usr/lib/phantowd/qemu-nfs-code-expected.json")
	if err != nil {
		os.Exit(1)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 128<<10 {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if sourceLoss {
		if err := probeSourceLossRuntime(ctx, data); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_LOSS_REFUSED")
			os.Exit(1)
		}
		return
	}
	if sourceFixture {
		if err := probeSourceRuntime(ctx, data); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_REFUSED")
			os.Exit(1)
		}
		return
	}
	if err := runtimebundle.ProbeNFSCodeQEMU(ctx, data); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_CODE_PROBE_REFUSED")
		os.Exit(1)
	}
}

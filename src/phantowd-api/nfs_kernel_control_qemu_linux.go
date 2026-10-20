//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"os"
	"runtime"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

var errQEMUNFSKernel = nfskernel.ErrRefused

type qemuNFSKernel = nfskernel.ControllerQEMU

// Policy retention stays with the existing reboot fixture, not the kernel module.
var qemuNFSKernelRetention struct {
	sync.Mutex
	policies []*qemuNFSRebootPolicy
}

func qemuNFSKernelPort(fd int) ([]byte, error) { return nfskernel.SocketRequestQEMU(fd) }

func openQEMUNFSKernel(ctx context.Context) (*qemuNFSKernel, error) {
	// Preserve the original exact virtual-data-disk admission before the shared
	// fixed controller. The additional package guard requires the reboot selector.
	if ctx == nil || ctx.Err() != nil || runtime.GOARCH != "arm" || os.Geteuid() != 0 || runQEMUNFSTest("verify-disk") != nil {
		return nil, errQEMUNFSKernel
	}
	return nfskernel.OpenRebootQEMU(ctx)
}

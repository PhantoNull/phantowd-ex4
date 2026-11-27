//go:build linux && qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nftguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
)

// NewSambaLoopbackFixture pins the fixed endpoint in the NIC-less ARMv5
// fixture. The ordinary image constructor requires an Ethernet interface.
func NewSambaLoopbackFixture(ctx context.Context, domain func(context.Context) error, code *os.File) (*Samba, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	device, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	return newSamba(ctx, domain, netip.MustParseAddr("192.0.2.21"), device.Index, code, true)
}

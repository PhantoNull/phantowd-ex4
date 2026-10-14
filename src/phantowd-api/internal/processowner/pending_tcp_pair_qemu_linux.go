//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"net/netip"
)

// Copied connection observations only, not process, namespace, SMB handle or
// request authority. Callers must independently qualify their retained census
// and completed same-namespace dump. No PID/descriptor is opened or returned.
type pendingTCPPairQEMU struct {
	client, server pendingTCPSocketQEMU
}

func matchPendingTCPPairQEMU(ctx context.Context, rows []pendingTCPSocketQEMU, clientInode, serverInode uint32) (pendingTCPPairQEMU, error) {
	if ctx == nil {
		return pendingTCPPairQEMU{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	if len(rows) < 2 || len(rows) > maxPendingTCPSocketsQEMU || clientInode == 0 || serverInode == 0 || clientInode == serverInode {
		return pendingTCPPairQEMU{}, ErrUnavailable
	}
	var pair pendingTCPPairQEMU
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return pendingTCPPairQEMU{}, err
		}
		if !row.local.Addr().Is4() || !row.peer.Addr().Is4() || row.local.Addr().IsUnspecified() || row.peer.Addr().IsUnspecified() ||
			row.local.Port() == 0 || row.peer.Port() == 0 || row.inode == 0 || row.cookie == 0 || row.cookie == ^uint64(0) {
			return pendingTCPPairQEMU{}, ErrUnavailable
		}
		for _, earlier := range rows[:i] {
			if earlier.inode == row.inode || earlier.cookie == row.cookie || earlier.local == row.local && earlier.peer == row.peer {
				return pendingTCPPairQEMU{}, ErrUnavailable
			}
		}
		if row.inode == clientInode {
			pair.client = row
		} else if row.inode == serverInode {
			pair.server = row
		}
	}
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	service := netip.AddrPortFrom(loopback, 1445) // Fixed disposable Samba fixture.
	if pair.client.inode == 0 || pair.server.inode == 0 || pair.client.local.Addr() != loopback ||
		pair.client.local.Port() == 1445 || pair.client.peer != service || pair.server.local != service ||
		pair.server.peer != pair.client.local || pair.client.interfaceID != 0 || pair.server.interfaceID != 0 {
		return pendingTCPPairQEMU{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	return pair, nil
}

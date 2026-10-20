//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import "bytes"

func rpcBindReplyQEMU(data []byte) bool {
	// One final TCP record: fixed XID, accepted RPC reply, AUTH_NONE verifier,
	// SUCCESS for the fixed rpcbind v2 NULL call. No mapping mutation or payload.
	return bytes.Equal(data, []byte{0x80, 0, 0, 24, 0x50, 0x48, 0x4e, 1,
		0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"encoding/hex"
	"testing"
)

func TestNFSRPCBindReplyRequiresExactAcceptedNullRecord(t *testing.T) {
	data, err := hex.DecodeString("8000001850484e010000000100000000000000000000000000000000")
	if err != nil || !rpcBindReplyQEMU(data) {
		t.Fatal("exact fixed NULL reply refused", err)
	}
	for index := range data {
		changed := append([]byte(nil), data...)
		changed[index] ^= 1
		if rpcBindReplyQEMU(changed) {
			t.Fatalf("changed record byte %d accepted", index)
		}
	}
	for _, changed := range [][]byte{nil, data[:len(data)-1], append(append([]byte(nil), data...), 0)} {
		if rpcBindReplyQEMU(changed) {
			t.Fatal("partial or extra record admitted")
		}
	}
}

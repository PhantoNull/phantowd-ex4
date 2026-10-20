//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner_test

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSMountdStartupWaitsForExactFragmentedNotice(t *testing.T) {
	want := []byte("PHANTOWD_NFS_MOUNTD_HANDOFF private_view=true capabilities_zero=true channels=3 active_interfaces=lo fixed_mountd=true\nrpc.mountd: Version 2.8.6 starting\n")
	for length := 0; length <= len(want); length++ {
		ready, err := processowner.NFSMountdStartupReadyQEMU(want[:length])
		if err != nil || ready != (length == len(want)) {
			t.Fatal("valid fragmented startup misclassified", length, ready, err)
		}
	}
	for _, data := range [][]byte{append(append([]byte(nil), want...), '!'), []byte("warning\n"), []byte("rpc.mountd: Version 2.8.6 starting\n"), append([]byte("error\n"), want...), append(append([]byte(nil), want...), '\r')} {
		if ready, err := processowner.NFSMountdStartupReadyQEMU(data); ready || err == nil {
			t.Fatal("unexpected startup accepted or treated as pending")
		}
	}
}

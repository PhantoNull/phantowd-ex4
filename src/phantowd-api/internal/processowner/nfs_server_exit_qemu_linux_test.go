//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package processowner

import (
	"strings"
	"testing"
)

func TestNFSServerPeerCommandRequiresDedicatedUnmixedProfile(t *testing.T) {
	base := "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 "
	flag := "phantowd_nfs_source_owner_daemon_loss_fixture=1"
	stop := "phantowd_nfs_source_owner_stop_loss_fixture=1"
	for _, command := range []string{"", base, flag, base + flag + " " + flag,
		base + flag + " " + strings.ReplaceAll(stop, "=1", "=0"), base + flag + " " + stop + " " + stop,
		base + strings.ReplaceAll(flag, "=1", "=0"), base + flag + " phantowd_nfs_source_loss_fixture=1",
		base + flag + " phantowd_nfs_source_daemon_loss_fixture=1", base + flag + " phantowd_nfs_source_owner_policy_loss_fixture=1",
		base + flag + " phantowd_nfs_code_fixture=0", base + flag + " phantowd_nfs_code_fixture=1",
		base + flag + " phantowd_nfs_source_fixture=0", base + flag + " phantowd_nfs_source_fixture=1", strings.Repeat("x", 4097)} {
		if nfsServerPeerCommandQEMU([]byte(command)) {
			t.Fatal("incorrect fault command admitted", command)
		}
	}
	if !nfsServerPeerCommandQEMU([]byte("console=ttyAMA0 " + base + flag + " ro")) {
		t.Fatal("exact dedicated fault command refused")
	}
	if !nfsServerPeerCommandQEMU([]byte(base + flag + " " + stop)) {
		t.Fatal("exact stop subprofile refused")
	}
}

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
		base + flag + " phantowd_nfs_source_owner_rpc_start_failure_fixture=1",
		base + flag + " phantowd_nfs_source_owner_kernel_construct_refusal_fixture=1",
		base + flag + " phantowd_nfs_future_fixture=1", base + flag + " phantowd_nfs_future_fixture=0",
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

func TestNFSFaultCommandProfilesAreClosed(t *testing.T) {
	values := []string{"phantowd_nfs_code_fixture=1", "phantowd_nfs_source_fixture=1", "phantowd_nfs_source_loss_fixture=1", "phantowd_nfs_source_daemon_loss_fixture=1", "phantowd_nfs_source_owner_daemon_loss_fixture=1", "phantowd_nfs_source_owner_stop_loss_fixture=1"}
	for mask := 0; mask < 64; mask++ {
		var words []string
		for index, value := range values {
			if mask&(1<<index) != 0 {
				words = append(words, value)
			}
		}
		command := "console=ttyAMA0 " + strings.Join(words, "\t") + "\r\nquiet"
		source := mask == 7 || mask == 15
		peer := mask == 15
		server := mask == 19 || mask == 51
		if nfsSourceCleanupCommandQEMU([]byte(command)) != source || nfsSourcePeerCommandQEMU([]byte(command)) != peer || nfsServerPeerCommandQEMU([]byte(command)) != server {
			t.Fatal("closed known-flag truth table mismatch", mask)
		}
	}
	for _, base := range []string{strings.Join(values[:3], " "), strings.Join(values[:4], " "), values[0] + " " + values[1] + " " + values[4]} {
		invalid := []string{base + "\x00", strings.Repeat("x", 4097)}
		for _, flag := range []string{"phantowd_nfs_future_fixture=1", "phantowd_nfs_future_fixture=0", "phantowd_nfs_future_fixture", "phantowd_nfs_source_owner_rpc_start_failure_fixture=1", "phantowd_nfs_source_owner_kernel_construct_refusal_fixture=1", "phantowd_nfs_source_owner_policy_loss_fixture=1", values[0]} {
			invalid = append(invalid, base+" "+flag)
		}
		for _, command := range invalid {
			if nfsSourceCleanupCommandQEMU([]byte(command)) || nfsSourcePeerCommandQEMU([]byte(command)) || nfsServerPeerCommandQEMU([]byte(command)) {
				t.Fatal("unknown, malformed, duplicate or sibling profile admitted", command)
			}
		}
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"strings"
	"testing"
)

func TestOwnerStopLossSelectorRequiresDedicatedBaseAndExactStopFlag(t *testing.T) {
	base := "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 phantowd_nfs_source_owner_daemon_loss_fixture=1 "
	flag := "phantowd_nfs_source_owner_stop_loss_fixture=1"
	for _, tc := range []struct {
		text            string
		selected, valid bool
	}{
		{"", false, true}, {base, false, true}, {flag, true, false}, {base + flag, true, true},
		{base + flag + " " + flag, true, false}, {base + strings.ReplaceAll(flag, "=1", "=0"), true, false},
		{base + flag + " phantowd_nfs_source_owner_policy_loss_fixture=1", true, false},
		{base + flag + " phantowd_nfs_source_loss_fixture=1", true, false},
		{base + flag + " phantowd_nfs_source_daemon_loss_fixture=1", true, false},
		{strings.ReplaceAll(base, "phantowd_nfs_source_owner_daemon_loss_fixture=1 ", "") + flag, true, false},
		{base + flag + " phantowd_nfs_code_fixture=1", true, false}, {base + flag + " phantowd_nfs_source_fixture=0", true, false},
		{strings.Repeat("x", 4097), false, false},
	} {
		selected, valid := parseOwnerStopLossSelector([]byte(tc.text))
		if selected != tc.selected || valid != tc.valid {
			t.Fatal("invalid explicit-stop profile", tc.text, selected, valid)
		}
	}
}

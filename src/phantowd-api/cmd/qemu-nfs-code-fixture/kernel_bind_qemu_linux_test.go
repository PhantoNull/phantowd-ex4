//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"strings"
	"testing"
)

func TestKernelBindSelectorRequiresDedicatedUnmixedSourceInit(t *testing.T) {
	base := "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 init=/usr/sbin/phantowd-nfs-kernel-bind-init"
	if selected, valid := parseKernelBindSelectorQEMU([]byte(base)); !selected || !valid {
		t.Fatal("dedicated source init refused")
	}
	for _, value := range []string{base + " init=/init", base + "\x00", strings.Repeat("x", 4097),
		base + " phantowd_nfs_code_fixture=1", base + " phantowd_nfs_future=1",
		base + " phantowd_nfs_source_owner_rpc_start_failure_fixture=1", strings.ReplaceAll(base, "source_fixture=1", "source_fixture=0")} {
		if _, valid := parseKernelBindSelectorQEMU([]byte(value)); valid {
			t.Fatal("mixed or malformed dedicated profile admitted")
		}
	}
	if selected, valid := parseKernelBindSelectorQEMU([]byte("phantowd_nfs_code_fixture=1 init=/init")); selected || !valid {
		t.Fatal("ordinary profile changed")
	}
}

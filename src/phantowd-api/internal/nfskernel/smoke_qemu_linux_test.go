//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel

import (
	"strings"
	"testing"
)

func TestSmokeSelectorIsExplicitAndExclusive(t *testing.T) {
	for _, role := range []string{"code", "reboot", "smoke", "unknown"} {
		for _, command := range []string{
			"", "phantowd_nfs_kernel_smoke=0",
			"phantowd_nfs_kernel_smoke=1 phantowd_nfs_kernel_smoke=1",
			"phantowd_nfs_kernel_smoke=1 phantowd.state=seed",
			"phantowd_nfs_kernel_smoke=1 phantowd_nfs_code_fixture=1",
			"phantowd_nfs_kernel_smoke=1 phantowd_nfs_code_fixture=2",
			"phantowd_nfs_kernel_smoke=1" + strings.Repeat(" ", 4096),
		} {
			if fixtureCommandQEMU([]byte(command), role) {
				t.Fatalf("mixed, invalid or absent selector admitted for %s", role)
			}
		}
		if got := fixtureCommandQEMU([]byte("console=ttyAMA0 phantowd_nfs_kernel_smoke=1"), role); got != (role == "smoke") {
			t.Fatalf("wrong smoke admission for %s", role)
		}
	}
	if !fixtureCommandQEMU([]byte("phantowd_nfs_code_fixture=1"), "code") || !fixtureCommandQEMU([]byte("phantowd.state=verify"), "reboot") {
		t.Fatal("original fixture selectors changed")
	}
}

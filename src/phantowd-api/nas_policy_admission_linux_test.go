//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNASPolicyAdmissionRequiresNonRootTLS(t *testing.T) {
	for _, c := range []struct {
		uid, euid, gid int
		legacy, tls    bool
		want           bool
	}{
		{1000, 1000, 1000, false, true, true},
		{0, 1000, 1000, false, true, false}, {1000, 0, 1000, false, true, false},
		{1000, 1000, 0, false, true, false}, {1000, 1000, 1000, false, false, false},
		{1000, 1000, 1000, true, true, false},
		{1000, 1000, 65535, false, true, false},
	} {
		if nasPolicyStartupAllowed("/run/provider/channel", c.legacy, c.tls, c.uid, c.euid, c.gid) != c.want {
			t.Fatal("startup admission differs", c)
		}
	}
}

func TestNASPolicyAdmissionMetadata(t *testing.T) {
	parent := unix.Stat_t{Mode: unix.S_IFDIR | 0710, Uid: 0, Gid: 1000, Dev: 7}
	socket := unix.Stat_t{Mode: unix.S_IFSOCK | 0660, Uid: 0, Gid: 1000, Dev: 7, Nlink: 1}
	if !nasPolicyParentSafe(parent, 1000) || !nasPolicySocketSafe(socket, parent, 1000) {
		t.Fatal("protected provider metadata refused")
	}
	for name, change := range map[string]func(*unix.Stat_t){
		"mode":  func(s *unix.Stat_t) { s.Mode |= 0002 },
		"owner": func(s *unix.Stat_t) { s.Uid = 1000 },
		"group": func(s *unix.Stat_t) { s.Gid = 1001 },
	} {
		p, s := parent, socket
		change(&p)
		change(&s)
		if nasPolicyParentSafe(p, 1000) || nasPolicySocketSafe(s, parent, 1000) {
			t.Fatal("unsafe provider metadata admitted", name)
		}
	}
	for _, s := range []unix.Stat_t{{}, {Mode: unix.S_IFREG | 0660, Gid: 1000, Dev: 7, Nlink: 1},
		{Mode: socket.Mode, Gid: 1000, Dev: 8, Nlink: 1}, {Mode: socket.Mode, Gid: 1000, Dev: 7, Nlink: 2}} {
		if nasPolicySocketSafe(s, parent, 1000) {
			t.Fatal("missing/invalid socket admitted")
		}
	}
}

func TestNASPolicyOwnerServiceRefusesHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("actual ARM proof runs only in the guarded QEMU guest")
	}
	if runQEMUNASPolicyOwnerService() == nil {
		t.Fatal("host admitted as QEMU provider")
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestNFSPolicyAccessMustMatchTheAppliedRevision(t *testing.T) {
	const path = "/fixed-export"
	line := func(access string) string {
		return path + " 127.0.0.1/32(" + access + ",all_squash,anonuid=1234,anongid=1235,fsid=bbbbbbbb-cccc-dddd-eeee-ffffffffffff)"
	}
	for _, tc := range []struct {
		name, actual, desired string
		accepted              bool
	}{
		{"read-only", "ro", "ro", true},
		{"read-write", "rw", "rw", true},
		{"stale-read-only", "ro", "rw", false},
		{"unexpected-write", "rw", "ro", false},
		{"mixed", "ro,rw", "rw", false},
		{"duplicate", "rw,rw", "rw", false},
		{"missing", "sync", "rw", false},
		{"invalid-desired", "rw", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesQEMUOwnerMountedExportAccess(line(tc.actual), path, 1234, 1235, tc.desired); got != tc.accepted {
				t.Fatalf("access match=%t, want %t", got, tc.accepted)
			}
		})
	}
	if matchesQEMUOwnerMountedExport(line("rw"), path, 1234, 1235) {
		t.Fatal("the existing read-only fixture accepted write access")
	}
}

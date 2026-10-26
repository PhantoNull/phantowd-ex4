//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNASPolicyStartupDisabledAndInvalidOptions(t *testing.T) {
	auth, _ := newTestAuth(t)
	h, close, err := openNASPolicyHTTP(auth, "", true, false)
	if err != nil || h != nil || close == nil || close() != nil || close() != nil {
		t.Fatal("disabled channel changed default startup")
	}
	for _, tc := range []struct {
		path        string
		legacy, tls bool
	}{
		{"relative/channel", false, true}, {"/run/x/../x/channel", false, true},
		{"/run/x/other", false, true}, {"/run/x/channel", true, true},
		{"/run/x/channel", false, false},
	} {
		h, close, err := openNASPolicyHTTP(auth, tc.path, tc.legacy, tc.tls)
		if err == nil || h != nil || close != nil {
			t.Fatal("invalid startup supplied authority", tc)
		}
	}
	if h, close, err := openNASPolicyHTTP(nil, "/run/x/channel", false, true); err == nil || h != nil || close != nil {
		t.Fatal("missing auth configured channel")
	}
}

func TestNASPolicyStartupDoesNotRepairUntrustedDirectory(t *testing.T) {
	auth, _ := newTestAuth(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "keep")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, close, err := openNASPolicyHTTP(auth, filepath.Join(dir, "channel"), false, true)
	if err == nil || h != nil || close != nil {
		t.Fatal("untrusted directory admitted")
	}
	after, statErr := os.Stat(dir)
	entries, readErr := os.ReadDir(dir)
	data, dataErr := os.ReadFile(sentinel)
	if statErr != nil || readErr != nil || dataErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || len(entries) != 1 || string(data) != "preserve" {
		t.Fatal("refusal repaired or changed files")
	}
}

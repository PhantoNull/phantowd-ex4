//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUSMBStatusTableReturnsOnlyFixedTargetPIDs(t *testing.T) {
	status := []byte("Samba version 4.22.11\n\n" +
		"PID     Username     Group        Machine                                  Protocol Version  Encryption          Signing\n" +
		"----------------------------------------------------------------------------------------------------------------------------------------\n" +
		"71      qpwriter     qpgroup      127.0.0.1 (ipv4:127.0.0.1:51001)          SMB3_11           -                   -\n" +
		"72      qpwriter     qpgroup      127.0.0.1 (ipv4:127.0.0.1:51002)          SMB3_11           -                   -\n" +
		"73      qpreader     qpgroup      127.0.0.1 (ipv4:127.0.0.1:51003)          SMB3_11           -                   -\n\n")

	got, err := parseQEMUSMBStatusTable(status, "qpwriter")
	if err != nil {
		t.Fatal("parse smbstatus session table:", err)
	}
	want := []qemuSMBServerID{{PID: 71}, {PID: 72}}
	if len(got) != len(want) {
		t.Fatalf("target worker count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target worker %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestQEMUSMBStatusTableRejectsChangedOrGenerationQualifiedRows(t *testing.T) {
	for _, status := range [][]byte{
		[]byte("JSON support not available, please install lib Jansson\n"),
		[]byte("PID Username Group Machine Protocol Version Encryption Signing\n"),
		[]byte("PID Username Group Machine Protocol Version Encryption Signing\n71 qpwriter qpgroup machine SMB3_11 - -\n"),
		[]byte("PID Username Group Machine Protocol Version Encryption Signing\n---\n71/9001 qpwriter qpgroup machine SMB3_11 - -\n"),
	} {
		if got, err := parseQEMUSMBStatusTable(status, "qpwriter"); err == nil || got != nil {
			t.Fatalf("unexpected or generation-qualified status format accepted: sessions=%#v error=%v", got, err)
		}
	}
}

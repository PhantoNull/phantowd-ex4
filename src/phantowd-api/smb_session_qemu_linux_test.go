//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUSMBStatusJSONReturnsOnlyTargetGenerations(t *testing.T) {
	status := []byte("{\"sessions\":{" +
		"\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"9001\"},\"username\":\"qpwriter\"}," +
		"\"2\":{\"session_id\":\"2\",\"server_id\":{\"pid\":\"72\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"9002\"},\"username\":\"qpwriter\"}," +
		"\"3\":{\"session_id\":\"3\",\"server_id\":{\"pid\":\"73\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"9003\"},\"username\":\"qpreader\"}}}")

	got, err := parseQEMUSMBStatusJSON(status, "qpwriter")
	if err != nil {
		t.Fatal("parse smbstatus session JSON:", err)
	}
	want := []qemuSMBServerID{{PID: 71, UniqueID: 9001}, {PID: 72, UniqueID: 9002}}
	if len(got) != len(want) {
		t.Fatalf("target worker count = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target worker %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestQEMUSMBStatusJSONRejectsUnavailableOrUnqualifiedSessions(t *testing.T) {
	for _, status := range [][]byte{
		[]byte("JSON support not available, please install lib Jansson\n"),
		[]byte("{\"sessions\":"),
		[]byte("{\"version\":\"4.22.11\"}"),
		[]byte("{\"sessions\":null}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"2\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"9001\"},\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"0\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"9001\"},\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"1\",\"vnn\":\"4294967295\",\"unique_id\":\"9001\"},\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"0\",\"vnn\":\"0\",\"unique_id\":\"9001\"},\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"18446744073709551615\"},\"username\":\"qpwriter\"}}}"),
		[]byte("{\"sessions\":{\"1\":{\"session_id\":\"1\",\"server_id\":{\"pid\":\"71\",\"task_id\":\"0\",\"vnn\":\"4294967295\",\"unique_id\":\"0\"},\"username\":\"qpwriter\"}}}"),
	} {
		if got, err := parseQEMUSMBStatusJSON(status, "qpwriter"); err == nil || got != nil {
			t.Fatalf("incomplete or unqualified status accepted: sessions=%#v error=%v", got, err)
		}
	}
}

func TestQEMUSMBStatusJSONAcceptsEmptySessionInventory(t *testing.T) {
	got, err := parseQEMUSMBStatusJSON([]byte("{\"sessions\":{}}"), "qpwriter")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty session inventory = %#v, error %v", got, err)
	}
}

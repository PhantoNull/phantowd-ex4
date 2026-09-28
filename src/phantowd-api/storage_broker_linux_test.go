//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorageBrokerTasksRequireNoNewPrivilegesOnEveryThread(t *testing.T) {
	taskDirectory := t.TempDir()
	writeTaskStatus := func(tid string, noNewPrivs string) {
		t.Helper()
		path := filepath.Join(taskDirectory, tid)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal("create task fixture")
		}
		status := "Name:\tphantowd-api\nNoNewPrivs:\t" + noNewPrivs + "\n"
		if err := os.WriteFile(filepath.Join(path, "status"), []byte(status), 0600); err != nil {
			t.Fatal("write task status fixture")
		}
	}

	writeTaskStatus("101", "1")
	writeTaskStatus("102", "1")
	restricted, err := storageBrokerTasksHaveNoNewPrivileges(taskDirectory)
	if err != nil || !restricted {
		t.Fatal("fully restricted broker task set was rejected")
	}

	if err := os.WriteFile(filepath.Join(taskDirectory, "102", "status"),
		[]byte("Name:\tphantowd-api\nNoNewPrivs:\t0\n"), 0600); err != nil {
		t.Fatal("write unrestricted task fixture")
	}
	restricted, err = storageBrokerTasksHaveNoNewPrivileges(taskDirectory)
	if err != nil || restricted {
		t.Fatal("task set with one unrestricted thread was accepted")
	}

	if err := os.WriteFile(filepath.Join(taskDirectory, "102", "status"),
		[]byte("Name:\tphantowd-api\n"), 0600); err != nil {
		t.Fatal("write incomplete task fixture")
	}
	if _, err := storageBrokerTasksHaveNoNewPrivileges(taskDirectory); err == nil {
		t.Fatal("task status without NoNewPrivs was accepted")
	}
}

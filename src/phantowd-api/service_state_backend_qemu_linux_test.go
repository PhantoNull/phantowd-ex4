//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQEMUServiceStateBackend(t *testing.T) {
	backend, closeDisabled, err := openDevelopmentServiceState("")
	if err != nil || backend != nil || closeDisabled == nil || closeDisabled() != nil {
		t.Fatal("disabled backend changed")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backend, closeState, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeState()
	if c, err := backend.load(); err != nil || c != nil {
		t.Fatal("uninitialized state not preserved", err)
	}
	if _, closeOther, err := openDevelopmentServiceState(dir); err == nil {
		closeOther()
		t.Fatal("competing owner accepted")
	}
	want := qemuPersistentServices(1)
	if err := backend.commit(0, want); err != nil {
		t.Fatal(err)
	}
	if err := backend.commit(0, want); !errors.Is(err, errServiceStateConflict) {
		t.Fatal("stale revision was not translated", err)
	}
	if err := closeState(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.load(); err == nil {
		t.Fatal("closed store readable")
	}
	if err := backend.commit(1, qemuPersistentServices(2)); err == nil {
		t.Fatal("closed store writable")
	}
	reopened, closeAgain, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgain()
	if got, err := reopened.load(); err != nil || got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatal("committed state lost", err)
	}
	for _, invalid := range []string{filepath.Join(dir, "missing"), "."} {
		if _, closeOther, err := openDevelopmentServiceState(invalid); err == nil {
			closeOther()
			t.Fatal("invalid state accepted")
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
)

// Non-Linux tests exercise controller semantics, not filesystem guarantees.
// This backend exists only in test binaries; firmware has no memory fallback.
type memoryAccountBackend struct {
	document      admincredentials.Document
	loadErr       error
	initializeErr error
	closed        bool
}

func (b *memoryAccountBackend) Load() (admincredentials.Document, error) {
	if b.closed {
		return admincredentials.Document{}, errAccountClosed
	}
	if b.loadErr != nil {
		return admincredentials.Document{}, b.loadErr
	}
	if b.document.Revision == 0 {
		return admincredentials.Document{}, errAccountMissing
	}
	return b.document, nil
}

func (b *memoryAccountBackend) Initialize(name, verifier string) error {
	if b.closed {
		return errAccountClosed
	}
	if b.initializeErr != nil {
		return b.initializeErr
	}
	if b.document.Revision != 0 {
		return errAccountConfigured
	}
	b.document = admincredentials.Document{Version: admincredentials.Version, Revision: 1,
		Admin: admincredentials.Account{Username: name, PasswordHash: verifier}}
	return nil
}

func (b *memoryAccountBackend) Close() error { b.closed = true; return nil }

func openTestAccountStore(t *testing.T, dir string) *accountStore {
	t.Helper()
	var s *accountStore
	if runtime.GOOS == "linux" {
		var err error
		s, err = openAccountStore(dir)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		s = &accountStore{backend: &memoryAccountBackend{}}
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNoNonLinuxPersistentFallback(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	if s, err := openAccountStore(t.TempDir()); err == nil {
		s.Close()
		t.Fatal("non-Linux firmware accepted an unqualified account backend")
	}
}

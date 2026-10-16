//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Exact persistence-codec parity on synthetic temporary state, NOT a journal
// transaction: this test deliberately creates no durable intent or receipt.
func TestPreparedCandidateMatchesActualStorePersistence(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := naspolicystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Commit(0, nextPolicy(t, 1)); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join(dir, "nas-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(installation, base, nextPolicy(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := p.CandidateBytes()
	next, err := naspolicy.Decode(bytes.NewReader(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(1, next); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(dir, "nas-services.json"))
	if err != nil || !bytes.Equal(persisted, candidate) {
		t.Fatal("prepared bytes differ from actual Store publication")
	}
	i, _ := p.Intent()
	intent, _ := EncodeIntent(i)
	d, err := Match(Evidence{InstallationID: installation, Intent: Slot{Present, intent}, Receipt: Slot{State: Absent}, Current: Slot{Present, persisted}})
	if err != nil || d.Kind() != PublicationUnconfirmed {
		t.Fatal("parity test falsely confirmed an operation", d, err)
	}
	names, err := os.ReadDir(dir)
	if err != nil || len(names) != 1 || names[0].Name() != "nas-services.json" {
		t.Fatal("unexpected prepared persistence or leftover staging")
	}
}

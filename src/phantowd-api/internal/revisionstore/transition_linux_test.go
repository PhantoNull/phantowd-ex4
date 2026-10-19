//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestTransitionRefusalPreservesPolicyPendingAndAllowsLaterValidCommit(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	codec := shareCodec()
	detail := errors.New("private transition detail")
	codec.ValidateTransition = func(_, next shareconfig.Config) error {
		if len(next.Users) == 0 {
			return detail
		}
		return nil
	}
	store, err := OpenWithCodec(dir, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Initialization has no previous document and must not fabricate one.
	if err := store.Commit(0, policy(1)); err != nil {
		t.Fatal("transition-only validator blocked initialization", err)
	}
	if err := store.Commit(0, policy(1)); !errors.Is(err, ErrConflict) {
		t.Fatal("transition validation displaced stale-writer refusal", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, currentName))
	if err != nil {
		t.Fatal(err)
	}
	const evidence = "uncommitted evidence retained by validation refusal"
	if err := os.WriteFile(filepath.Join(dir, pendingName), []byte(evidence), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(1, policy(2)); err != ErrInvalid || errors.Is(err, detail) {
		t.Fatal("transition refusal was not the constant redacted error", err)
	}
	if after, err := os.ReadFile(filepath.Join(dir, currentName)); err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected transition rewrote current state", err)
	}
	if pending, err := os.ReadFile(filepath.Join(dir, pendingName)); err != nil || string(pending) != evidence {
		t.Fatal("rejected transition removed or changed pending evidence", err)
	}
	next := policy(2)
	next.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	if err := store.Commit(1, next); err != nil {
		t.Fatal("pure preflight refusal poisoned the legacy store", err)
	}
	if got, err := store.Load(); err != nil || got.Revision != 2 || len(got.Users) != 1 {
		t.Fatal("valid successor not published", err)
	}
}

func TestTransitionReceivesDecodedCandidateRatherThanCallerValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	codec := shareCodec()
	codec.Decode = func(input io.Reader) (shareconfig.Config, error) {
		doc, err := shareconfig.Decode(input)
		slices.SortFunc(doc.Users, func(a, b shareconfig.User) int { return strings.Compare(a.ID, b.ID) })
		return doc, err
	}
	codec.ValidateTransition = func(_, next shareconfig.Config) error {
		if len(next.Users) > 0 && next.Users[0].ID == "alice" {
			return ErrInvalid
		}
		return nil
	}
	store, err := OpenWithCodec(dir, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	next := policy(2)
	next.Users = []shareconfig.User{{ID: "zoe", Name: "zoe"}, {ID: "alice", Name: "alice"}}
	if err := store.Commit(1, next); !errors.Is(err, ErrInvalid) {
		t.Fatal("transition validator observed the caller's unnormalized order", err)
	}
	if next.Users[0].ID != "zoe" {
		t.Fatal("canonical validation mutated caller data")
	}
	if got, err := store.Load(); err != nil || got.Revision != 1 {
		t.Fatal("canonical transition refusal published candidate", err)
	}
}

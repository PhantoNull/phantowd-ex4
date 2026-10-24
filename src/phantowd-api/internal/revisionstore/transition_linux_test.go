// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestTransitionRefusalPreservesCurrentAndPending(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	codec, calls := shareCodec(), 0
	codec.Decode = func(input io.Reader) (shareconfig.Config, error) {
		c, err := shareconfig.Decode(input)
		if err == nil && len(c.Users) == 1 && c.Users[0].Name == "proposal" {
			c.Users[0].Name = "canonical"
		}
		return c, err
	}
	codec.ValidateTransition = func(current, next shareconfig.Config) error {
		calls++
		if current.Revision != 1 || current.Users[0].Name != "canonical" || next.Revision != 2 || next.Users[0].Name != "canonical" {
			t.Fatal("transition did not receive decoded current and next", current, next)
		}
		if next.Users[0].ID == "refused" {
			return errors.New("binding transition refused")
		}
		return nil
	}
	s, err := OpenWithCodec(dir, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	initial, next := policy(1), policy(2)
	initial.Users, next.Users = []shareconfig.User{{ID: "initial", Name: "proposal"}}, []shareconfig.User{{ID: "refused", Name: "proposal"}}
	if err := s.Commit(0, initial); err != nil || calls != 0 {
		t.Fatal("initialization evaluated a retained transition", err, calls)
	}
	if err := s.Commit(0, policy(1)); !errors.Is(err, ErrConflict) || calls != 0 {
		t.Fatal("stale CAS evaluated a transition", err, calls)
	}
	if err := os.WriteFile(filepath.Join(dir, pendingName), []byte("pending evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	before, stamps := map[string][]byte{}, map[string]os.FileInfo{}
	for _, name := range []string{currentName, pendingName} {
		if before[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if stamps[name], err = os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Commit(1, next); !errors.Is(err, ErrInvalid) || calls != 1 || next.Users[0].Name != "proposal" {
		t.Fatal("transition refusal lost or changed caller state", err, calls, next)
	}
	for name, want := range before {
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		stamp, statErr := os.Stat(filepath.Join(dir, name))
		if readErr != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(stamps[name], stamp) {
			t.Fatal("refusal changed current or pending evidence", name, readErr, statErr)
		}
	}
	next.Users[0].ID = "allowed"
	if err := s.Commit(1, next); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = OpenWithCodec(dir, codec); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || got.Revision != 2 || got.Users[0].ID != "allowed" || got.Users[0].Name != "canonical" || calls != 2 {
		t.Fatal("allowed transition did not survive reopen", got, err, calls)
	}
}

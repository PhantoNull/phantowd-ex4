// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/sharestore"
)

func TestSharePolicyReader(t *testing.T) {
	load, closeReader, err := openSharePolicyReader("")
	if err != nil || load != nil || closeReader == nil {
		t.Fatal("disabled reader", err)
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	load, closeReader, err = openSharePolicyReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	if policy, err := load(); policy != nil || err != nil {
		t.Fatal("uninitialized", policy, err)
	}
	if _, closeOther, err := openSharePolicyReader(dir); err == nil {
		closeOther()
		t.Fatal("lock missing")
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Fatal("closed reader loaded")
	}
	s, err := sharestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := testStoredPolicy()
	p.Revision = 1
	if err := s.Commit(0, *p); err != nil {
		t.Fatal(err)
	}
	s.Close()
	load, closeReader, err = openSharePolicyReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()
	first, err := load()
	if err != nil || first.Revision != 1 {
		t.Fatal("persisted read", err)
	}
	first.Revision = 88
	again, err := load()
	if err != nil || again.Revision != 1 {
		t.Fatal("snapshot alias", err)
	}
	closeReader()
	if err := os.WriteFile(filepath.Join(dir, "shares.json"), []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, closeReader, err := openSharePolicyReader(dir); err == nil {
		closeReader()
		t.Fatal("corruption accepted")
	}
	if _, closeReader, err := openSharePolicyReader(filepath.Join(dir, "absent")); err == nil {
		closeReader()
		t.Fatal("directory silently created")
	}
}

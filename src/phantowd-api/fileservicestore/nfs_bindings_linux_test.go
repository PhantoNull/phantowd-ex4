// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservicestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRejectsRetainedNFSRootChange(t *testing.T) {
	check := func(got, want error) {
		t.Helper()
		if !errors.Is(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	dir := t.TempDir()
	check(os.Chmod(dir, 0700), nil)
	s, err := Open(dir)
	check(err, nil)
	defer s.Close()
	check(s.Commit(0, policy(1)), nil)
	name := filepath.Join(dir, "file-services.json")
	before, err := os.ReadFile(name)
	check(err, nil)
	bad := policy(2)
	bad.NFS.Exports[0].RelativePath = "other"
	check(s.Commit(1, bad), ErrInvalid)
	if after, err := os.ReadFile(name); err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected root change altered current bytes", err)
	}
	next := policy(2)
	next.NFS.Exports[0].Clients[0].Access = "rw"
	check(s.Commit(1, next), nil)
	if got, err := s.Load(); err != nil || got.Revision != 2 || got.NFS.Exports[0].Clients[0].Access != "rw" {
		t.Fatal("client access change was not published", err)
	}
}

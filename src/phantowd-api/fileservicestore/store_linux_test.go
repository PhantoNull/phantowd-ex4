// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservicestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func policy(revision uint64) fileservice.Config {
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
			Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
			Users:   []shareconfig.User{{ID: "reader", Name: "reader"}},
			Shares:  []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
				Clients: []nfsconfig.Client{{Network: "192.0.2.10/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}}}
}

func TestCombinedStoreRejectsRetainedNFSBindingChangesBeforePublication(t *testing.T) {
	for _, kind := range []string{"root", "filesystem", "logical-volume"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			store, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.Commit(0, policy(1)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(dir, "file-services.json"))
			if err != nil {
				t.Fatal(err)
			}
			next := policy(2)
			switch kind {
			case "root":
				next.NFS.Exports[0].RelativePath = "unrelated"
			case "filesystem":
				next.Shares.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
			case "logical-volume":
				next.Shares.Volumes[0].ID = "other"
				next.Shares.Shares[0].VolumeID = "other"
				next.NFS.Exports[0].VolumeID = "other"
			}
			if err := store.Commit(1, next); !errors.Is(err, ErrInvalid) {
				t.Fatal("retained NFS binding changed", err)
			}
			if after, err := os.ReadFile(filepath.Join(dir, "file-services.json")); err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused binding update changed policy", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, ".file-services.pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused binding update created pending state", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if got, err := reopened.Load(); err != nil || !reflect.DeepEqual(got, policy(1)) {
				t.Fatal("refusal not preserved on reopen", err)
			}
			if err := reopened.Commit(1, policy(2)); err != nil {
				t.Fatal("valid successor blocked after pure refusal", err)
			}
		})
	}
}

func TestCombinedStorePublishesWholePolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); !errors.Is(err, ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	bad := policy(2)
	bad.NFS.VolumeRevision = 1
	if err := s.Commit(1, bad); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, policy(1)) {
		t.Fatal("split policy published", err)
	}
	next := policy(2)
	next.Shares.Shares[0].Grants[0].Access, next.NFS.Exports[0].Clients[0].Access = "rw", "rw"
	if err := s.Commit(1, next); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(1, policy(2)); !errors.Is(err, ErrConflict) {
		t.Fatal("stale writer", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	pending, _ := json.Marshal(policy(3))
	if err := os.WriteFile(filepath.Join(dir, ".file-services.pending"), pending, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err = s.Load()
	if err != nil || !reflect.DeepEqual(got, next) {
		t.Fatal("committed components changed on reopen", err)
	}
	got.NFS.Exports[0].Clients[0].Access = "ro"
	got.Shares.Volumes[0].ID = "mutated"
	again, err := s.Load()
	if err != nil || !reflect.DeepEqual(again, next) {
		t.Fatal("snapshot not independent", err)
	}
	if second, err := Open(dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "shares.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("share-only state modified")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{truncated")
	if err := os.WriteFile(filepath.Join(dir, "file-services.json"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(dir); !errors.Is(err, ErrInvalid) {
		if bad != nil {
			bad.Close()
		}
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"file-services.json": corrupt, ".file-services.pending": pending} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(data, want) {
			t.Fatal("evidence changed", err)
		}
	}
}

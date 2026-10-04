//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func emptyPolicy(revision uint64) naspolicy.Config {
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: revision,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
				Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
}

func TestAtomicNASPolicyLockingReopenAndEvidencePreservation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte("legacy evidence, not a NAS policy")
	if err := os.WriteFile(filepath.Join(dir, "file-services.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); !errors.Is(err, ErrNotInitialized) {
		t.Fatal("implicit legacy import", err)
	}
	if second, err := Open(dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("concurrent writer", err)
	}
	if err := s.Commit(0, emptyPolicy(1)); err != nil {
		t.Fatal(err)
	}
	bad := emptyPolicy(2)
	bad.ISCSI.Revision = 1
	if err := s.Commit(1, bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("mixed revision committed", err)
	}
	if err := s.Commit(0, emptyPolicy(1)); !errors.Is(err, ErrConflict) {
		t.Fatal("stale writer", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	pending, _ := json.Marshal(emptyPolicy(2))
	if err := os.WriteFile(filepath.Join(dir, ".nas-services.pending"), pending, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, emptyPolicy(1)) {
		t.Fatal("pending promoted", err)
	}
	got.ISCSI.Backings = append(got.ISCSI.Backings, iscsipolicy.Backing{ID: "local-only"})
	if again, err := s.Load(); err != nil || !reflect.DeepEqual(again, emptyPolicy(1)) {
		t.Fatal("shared snapshot", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{truncated")
	if err := os.WriteFile(filepath.Join(dir, "nas-services.json"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if broken, err := Open(dir); !errors.Is(err, ErrInvalid) {
		if broken != nil {
			broken.Close()
		}
		t.Fatal("corruption accepted", err)
	}
	for name, want := range map[string][]byte{"nas-services.json": corrupt, ".nas-services.pending": pending, "file-services.json": legacy} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(data, want) {
			t.Fatal("evidence/legacy changed", name, err)
		}
	}
}

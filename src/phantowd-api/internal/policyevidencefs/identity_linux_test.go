//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/identityevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestIdentityProfileNamesAndOriginalRosters(t *testing.T) {
	for _, name := range []string{"first", "account-123"} {
		if !identityRoleName(name) {
			t.Fatal("domain role refused")
		}
	}
	for _, name := range []string{"", "../first", "FIRST", "first/second", "first\x00"} {
		if identityRoleName(name) {
			t.Fatal("invalid role allowed")
		}
	}
	s := &state{watch: -1, identities: &identityLayout{dirs: make([]object, 6), files: make([]object, 4), roles: make([]roleSpec, 4), names: make([]map[string]stamp, 6)}}
	s.identities.names[5] = map[string]stamp{"fixed": {ino: 9}}
	if len(s.directoryObjects()) != 6 || len(s.fileObjects()) != 4 || len(s.roleSpecs()) != 4 || s.namesAt(5)["fixed"].ino != 9 || s.observationMode() != identityObservation {
		t.Fatal("wrong active roster")
	}
	s.directoryObjects()[5].initial.ino = 7
	s.fileObjects()[3].initial.ino = 8
	if s.identities.dirs[5].initial.ino != 7 || s.identities.files[3].initial.ino != 8 {
		t.Fatal("roster copies replaced originals")
	}
	a := &Observer{state: s}
	s.self = a
	s.review = true
	s.readAt = func(*os.File, []byte, int64) (int, error) { t.Fatal("pending read content"); return 0, ErrIO }
	if d, err := a.ObserveIdentity(context.Background()); err != ErrReview || d.Kind() != "" {
		t.Fatal("review produced data")
	}
	if _, err := a.Observe(context.Background()); err != ErrInvalid {
		t.Fatal("wrong profile admitted")
	}
	copy := *a
	if _, err := copy.ObserveIdentity(context.Background()); err != ErrInvalid {
		t.Fatal("copy admitted")
	}
}

func TestIdentityConstructorRootOnlyAndMissingEnrollmentRole(t *testing.T) {
	if a, err := OpenIdentity(nil, "/unavailable"); a != nil || err != ErrInvalid {
		t.Fatal("nil context")
	}
	if a, err := OpenIdentity(context.Background(), "relative"); a != nil || err != ErrInvalid {
		t.Fatal("relative path")
	}
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		if a, err := OpenIdentity(context.Background(), "/unavailable"); a != nil || err != ErrUnsafe {
			t.Fatal("non-root reached filesystem")
		}
	}
	s := &state{identities: &identityLayout{roles: make([]roleSpec, 1), accounts: []identityAccount{}}}
	d, err := s.matchIdentity([]policyevidence.Slot{{State: policyevidence.Absent}})
	if err != nil || d.Kind() != identityevidence.NoRecordedRegistry {
		t.Fatal("empty data comparison", err)
	}
}

func TestIdentityDynamicCloseStopsAtFirstUncertainty(t *testing.T) {
	root := t.TempDir()
	var files []*os.File
	for _, name := range []string{"root", "child", "record"} {
		p := filepath.Join(root, name)
		if os.WriteFile(p, []byte("synthetic"), 0600) != nil {
			t.Fatal("fixture")
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		defer f.Close()
	}
	s := &state{watch: -1, identities: &identityLayout{dirs: []object{{file: files[0]}, {file: files[1]}}, files: []object{{file: files[2]}}}}
	a := &Observer{state: s}
	s.self = a
	calls := 0
	s.closeFile = func(f *os.File) error {
		calls++
		if calls == 1 {
			return errors.New("controlled close refusal")
		}
		return f.Close()
	}
	if a.Close() != ErrReview || calls != 1 || s.identities.dirs[0].file != files[0] || s.identities.files[0].file != files[2] {
		t.Fatal("originals released on uncertainty")
	}
	if a.Close() != ErrReview || calls != 1 {
		t.Fatal("close retried")
	}
	if d, err := a.ObserveIdentity(context.Background()); err != ErrReview || d.Kind() != "" {
		t.Fatal("review resumed")
	}
}

func TestIdentityNativeOriginalLifetime(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("root-only identity constructor; positive lifetime not executed")
	}
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("mode")
	}
	for _, name := range []string{"registry", "operations"} {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			t.Fatal("layout")
		}
	}
	a, err := OpenIdentity(context.Background(), root)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("mandatory unique mount IDs unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if a.Close() != nil {
			t.Error("close")
		}
	}()
	for range 2 {
		d, err := a.ObserveIdentity(context.Background())
		if err != nil || d.Kind() != identityevidence.NoRecordedRegistry {
			t.Fatal("original empty namespace", err)
		}
	}
}

func TestIdentityCancelledDirectoryStepDoesNotOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &state{watch: -1, identities: &identityLayout{}}
	if err := s.openIdentityDirectory(ctx, -1, "/unavailable-identity-role", identityDirectory{}); err != context.Canceled || len(s.identities.dirs) != 0 {
		t.Fatal("canceled step attempted acquisition", err)
	}
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func anchoredFixture(t *testing.T) (*os.File, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "policy")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, child
}
func TestAnchoredStoreOwnsChildLockAndReturnsExactBytes(t *testing.T) {
	parent, dir := anchoredFixture(t)
	s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, b, err := s.LoadExact(); err != ErrNotInitialized || b != nil {
		t.Fatal("missing not explicit")
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	v, raw, err := s.LoadExact()
	encoded, _ := json.Marshal(policy(1))
	if err != nil || v.Revision != 1 || !bytes.Equal(raw, encoded) {
		t.Fatal("exact readback", err)
	}
	other, err := OpenWithCodec(dir, shareCodec())
	if other != nil {
		other.Close()
	}
	if err != ErrBusy {
		t.Fatal("actual child lock lost", err)
	}
	raw[0] = '!'
	if _, b, err := s.LoadExact(); err != nil || !bytes.Equal(b, encoded) {
		t.Fatal("returned byte aliases state")
	}
	if err := s.Commit(1, policy(2)); err != nil {
		t.Fatal("successful strict store cannot advance journal revision", err)
	}
}
func TestAnchoredOpenDoesNotSyncRewriteOrDiscardEvidence(t *testing.T) {
	parent, dir := anchoredFixture(t)
	data, _ := json.Marshal(policy(1))
	data = append(data, '\n')
	file := filepath.Join(dir, currentName)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	var before, after unix.Stat_t
	if unix.Stat(file, &before) != nil {
		t.Fatal("stat")
	}
	s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	if _, b, err := s.LoadExact(); err != nil || !bytes.Equal(b, data) {
		t.Fatal("canonicalized current", err)
	}
	s.Close()
	if unix.Stat(file, &after) != nil || before.Atim != after.Atim || policyStamp(before) != policyStamp(after) {
		t.Fatal("read-only open/read changed original metadata")
	}
	for _, name := range []string{pendingName, "unknown"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec()); err == nil {
			if s != nil {
				s.Close()
			}
			t.Fatal("unresolved evidence admitted")
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != "preserve" {
			t.Fatal("evidence discarded")
		}
		os.Remove(path)
	}
}
func TestAnchoredAnyAttemptedWriteFailurePermanentlyRefusesRetry(t *testing.T) {
	parent, dir := anchoredFixture(t)
	s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.io.write = func(f *os.File, b []byte) (int, error) {
		calls++
		n, err := f.Write(b[:3])
		if err != nil {
			return n, err
		}
		return n, unix.EIO
	}
	if err := s.Commit(1, policy(2)); err != ErrIO {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(dir, pendingName))
	if err != nil || len(staged) != 3 {
		t.Fatal("fault evidence missing")
	}
	if err := s.Commit(1, policy(2)); err != ErrUncertain || calls != 1 {
		t.Fatal("retry admitted", err)
	}
	if v, b, err := s.LoadExact(); err != ErrUncertain || b != nil || v.Revision != 0 {
		t.Fatal("partial observation escaped uncertainty")
	}
	s.Close()
	if s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec()); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("reopen discarded pending")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, pendingName)); !bytes.Equal(b, staged) {
		t.Fatal("pending changed across refusal")
	}
}
func TestAnchoredDirectoryReplacementAndParentCloseRefuse(t *testing.T) {
	for _, scenario := range []string{"replace", "parent-close"} {
		t.Run(scenario, func(t *testing.T) {
			parent, dir := anchoredFixture(t)
			s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if scenario == "replace" {
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				parent.Close()
			}
			if err := s.Commit(0, policy(1)); !errors.Is(err, ErrUncertain) {
				t.Fatal("lost parent/child accepted", err)
			}
		})
	}
	if s, err := OpenAnchoredWithCodec[shareconfig.Config](nil, "policy", shareCodec()); s != nil || err != ErrUnsafe {
		t.Fatal("nil parent")
	}
}

func TestAnchoredLateEntriesRefuseAllOperationsAndStayUncertain(t *testing.T) {
	for _, name := range []string{pendingName, "unknown"} {
		for _, operation := range []string{"load", "exact", "commit"} {
			t.Run(name+"/"+operation, func(t *testing.T) {
				parent, dir := anchoredFixture(t)
				s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if err := s.Commit(0, policy(1)); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte("evidence"), 0600); err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "load":
					_, err = s.Load()
				case "exact":
					_, _, err = s.LoadExact()
				case "commit":
					err = s.Commit(1, policy(2))
				}
				if err != ErrUncertain {
					t.Fatal("late entry admitted", err)
				}
				if b, e := os.ReadFile(path); e != nil || string(b) != "evidence" {
					t.Fatal("evidence changed")
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := s.Commit(1, policy(2)); err != ErrUncertain {
					t.Fatal("restoration cleared uncertainty")
				}
			})
		}
	}
}

func TestAnchoredEveryCommitStageFaultRefusesRetry(t *testing.T) {
	for _, stage := range []string{"short-write", "sync", "close", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			parent, dir := anchoredFixture(t)
			s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Commit(0, policy(1)); err != nil {
				t.Fatal(err)
			}
			original := s.io
			calls := 0
			switch stage {
			case "short-write":
				s.io.write = func(f *os.File, b []byte) (int, error) { calls++; return f.Write(b[:3]) }
			case "sync":
				s.io.sync = func(*os.File) error { calls++; return unix.EIO }
			case "close":
				s.io.close = func(f *os.File) error { calls++; _ = f.Close(); return unix.EIO }
			case "rename":
				s.io.rename = func(int, string, int, string) error { calls++; return unix.EIO }
			case "directory-sync":
				s.io.syncDir = func(int) error { calls++; return unix.EIO }
			}
			if err := s.Commit(1, policy(2)); err == nil || calls != 1 {
				t.Fatal("injected error accepted", err)
			}
			s.io = original
			before, err := os.ReadFile(filepath.Join(dir, currentName))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Commit(1, policy(2)); err != ErrUncertain || calls != 1 {
				t.Fatal("retry after fault", err)
			}
			if _, _, err := s.LoadExact(); err != ErrUncertain {
				t.Fatal("read after failed mutation")
			}
			after, _ := os.ReadFile(filepath.Join(dir, currentName))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed current")
			}
		})
	}
}

func TestAnchoredPreMutationRevisionRefusalDoesNotPoison(t *testing.T) {
	parent, _ := anchoredFixture(t)
	s, err := OpenAnchoredWithCodec(parent, "policy", shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Commit(0, policy(2)) != ErrConflict || s.Commit(0, policy(1)) != nil {
		t.Fatal("validation refusal either wrote or poisoned")
	}
}

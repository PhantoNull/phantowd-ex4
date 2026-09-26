// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package admincredentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"golang.org/x/sys/unix"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openTest(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func assertSnapshot(t *testing.T, s *Store, revision uint64, verifier string) {
	t.Helper()
	d, err := s.Load()
	if err != nil || d.Version != Version || d.Revision != revision ||
		d.Admin.Username != "nas-admin" || d.Admin.PasswordHash != verifier {
		t.Fatal("unexpected administrator credential snapshot", err)
	}
}

func TestInitializeReplaceAndReopen(t *testing.T) {
	dir := privateDirectory(t)
	s := openTest(t, dir)
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Replace(1, replacementVerifier); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Initialize("bad/name", fixtureVerifier); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize("other-admin", fixtureVerifier); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal(err)
	}
	if second, err := Open(dir); !errors.Is(err, revisionstore.ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("concurrent store owner accepted", err)
	}
	for _, revision := range []uint64{0, 2, math.MaxUint64} {
		if err := s.Replace(revision, replacementVerifier); !errors.Is(err, revisionstore.ErrConflict) {
			t.Fatal(err)
		}
	}
	for _, verifier := range []string{"", "invalid", fixtureVerifier} {
		if err := s.Replace(1, verifier); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	assertSnapshot(t, s, 1, fixtureVerifier)
	if err := s.Replace(1, replacementVerifier); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(1, fixtureVerifier); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Even a valid pending file cannot resurrect the old password.
	pending, _ := json.Marshal(document())
	if err := os.WriteFile(filepath.Join(dir, ".accounts.pending"), pending, 0600); err != nil {
		t.Fatal(err)
	}
	reopened := openTest(t, dir)
	assertSnapshot(t, reopened, 2, replacementVerifier)
	if err := reopened.Replace(2, fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	assertSnapshot(t, reopened, 3, fixtureVerifier)
}

func TestLegacyReadDoesNotRewriteOrReset(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "accounts.json")
	original := legacyDocument()
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	s := openTest(t, dir)
	assertSnapshot(t, s, 1, fixtureVerifier)
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, actual) {
		t.Fatal("read rewrote legacy credentials", err)
	}
	if err := s.Initialize("new-admin", replacementVerifier); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Replace(1, replacementVerifier); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTest(t, dir)
	assertSnapshot(t, reopened, 2, replacementVerifier)
	actual, err = os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(actual, []byte(`{"version":2,"revision":2,`)) {
		t.Fatal("replacement did not publish v2", err)
	}
}

func TestConcurrentReplacementHasOneWinner(t *testing.T) {
	s := openTest(t, privateDirectory(t))
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.Replace(1, replacementVerifier) }()
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, revisionstore.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 7 {
		t.Fatal("replacement was not single-writer")
	}
	assertSnapshot(t, s, 2, replacementVerifier)
}

func TestNoCachedCredentialsAfterCorruption(t *testing.T) {
	dir := privateDirectory(t)
	s := openTest(t, dir)
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "accounts.json")
	corrupt := []byte("{truncated")
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if d, err := s.Load(); !errors.Is(err, revisionstore.ErrInvalid) || d != (Document{}) {
		t.Fatal("cached verifier after corruption", err)
	}
	if err := s.Replace(1, replacementVerifier); !errors.Is(err, revisionstore.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.Initialize("nas-admin", fixtureVerifier); !errors.Is(err, revisionstore.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); !errors.Is(err, revisionstore.ErrInvalid) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, corrupt) {
		t.Fatal("corruption evidence replaced", err)
	}
}

func TestUnsafeCredentialEntriesAndStaging(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "public", "oversized", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDirectory(t)
			path := filepath.Join(dir, "accounts.json")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("absent", path)
			case "hardlink":
				original := filepath.Join(dir, "other")
				if err = os.WriteFile(original, legacyDocument(), 0600); err == nil {
					err = os.Link(original, path)
				}
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "public":
				err = os.WriteFile(path, legacyDocument(), 0644)
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), MaxBytes+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if s, err := Open(dir); !errors.Is(err, revisionstore.ErrUnsafe) {
				if s != nil {
					s.Close()
				}
				t.Fatal("accepted unsafe credential object", err)
			}
		})
	}
	dir := privateDirectory(t)
	s := openTest(t, dir)
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".accounts.pending"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(1, replacementVerifier); !errors.Is(err, revisionstore.ErrUnsafe) {
		t.Fatal(err)
	}
	assertSnapshot(t, s, 1, fixtureVerifier)
}

func TestZeroClosedAndExhaustedStore(t *testing.T) {
	var zero Store
	if _, err := zero.Load(); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := zero.Initialize("nas-admin", fixtureVerifier); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := zero.Replace(1, replacementVerifier); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
	dir := privateDirectory(t)
	d := document()
	d.Revision = math.MaxUint64
	data, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(dir, "accounts.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s := openTest(t, dir)
	if err := s.Replace(math.MaxUint64, replacementVerifier); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal(err)
	}
	assertSnapshot(t, s, math.MaxUint64, fixtureVerifier)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestReplacementSurvivesProcessExitWithoutReply(t *testing.T) {
	if dir := os.Getenv("PHANTOWD_ADMINSTORE_EXIT_FIXTURE"); dir != "" {
		s, err := Open(dir)
		if err != nil {
			os.Exit(24)
		}
		if s.Replace(1, replacementVerifier) != nil {
			os.Exit(25)
		}
		os.Exit(23) // Bypass Close/deferred cleanup and any acknowledgement.
	}
	dir := privateDirectory(t)
	s := openTest(t, dir)
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplacementSurvivesProcessExitWithoutReply$")
	cmd.Env = append(os.Environ(), "PHANTOWD_ADMINSTORE_EXIT_FIXTURE="+dir)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatal("replacement child did not reach exit boundary", err)
	}
	reopened := openTest(t, dir)
	assertSnapshot(t, reopened, 2, replacementVerifier)
	if err := reopened.Replace(1, fixtureVerifier); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal("replayed old revision", err)
	}
}

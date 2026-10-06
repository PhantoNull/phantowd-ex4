// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func policy(revision uint64) shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1,
		Revision: revision, Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

const currentName = "shares.json"
const pendingName = ".shares.pending"

func shareCodec() Codec[shareconfig.Config] {
	return Codec[shareconfig.Config]{CurrentName: currentName, PendingName: pendingName,
		MaxBytes: shareconfig.MaxInputBytes, Decode: shareconfig.Decode, Validate: shareconfig.Config.Validate,
		Revision: func(c shareconfig.Config) uint64 { return c.Revision }}
}

func Open(directory string) (*Store[shareconfig.Config], error) {
	return OpenWithCodec(directory, shareCodec())
}

func openTest(t *testing.T) (*Store[shareconfig.Config], string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestInitializeReopenAndRevision(t *testing.T) {
	s, dir := openTest(t)
	if _, err := s.Load(); !errors.Is(err, ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Commit(1, policy(2)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Commit(1, policy(3)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Commit(math.MaxUint64, policy(1)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	bad := policy(2)
	bad.Users = nil
	if err := s.Commit(1, bad); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.Commit(1, policy(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	c, err := reopened.Load()
	if err != nil || c.Revision != 2 {
		t.Fatalf("revision=%d error=%v", c.Revision, err)
	}
	st, err := os.Stat(filepath.Join(dir, currentName))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", st, err)
	}
}

func TestConcurrentUpdatesAndExclusiveOpen(t *testing.T) {
	s, dir := openTest(t)
	if second, err := Open(dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second store: %v", err)
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() { results <- s.Commit(1, policy(2)) })
	}
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful stale writers=%d", successes)
	}
}

func TestFailureBoundaries(t *testing.T) {
	for _, stage := range []string{"write", "short-write", "file-sync", "close", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			s, dir := openTest(t)
			if err := s.Commit(0, policy(1)); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "write":
				s.io.write = func(f *os.File, b []byte) (int, error) { n, _ := f.Write(b[:8]); return n, unix.ENOSPC }
			case "short-write":
				s.io.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:8]) }
			case "file-sync":
				s.io.sync = func(*os.File) error { return unix.EIO }
			case "close":
				s.io.close = func(f *os.File) error { f.Close(); return unix.EIO }
			case "rename":
				s.io.rename = func(int, string, int, string) error { return unix.EIO }
			case "directory-sync":
				s.io.syncDir = func(int) error { return unix.EIO }
			}
			err := s.Commit(1, policy(2))
			want := ErrIO
			expectedRevision := uint64(1)
			if stage == "rename" {
				want = ErrUncertain
			}
			if stage == "directory-sync" {
				want = ErrUncertain
				expectedRevision = 2
			}
			if !errors.Is(err, want) {
				t.Fatalf("commit=%v want=%v", err, want)
			}
			if want == ErrUncertain {
				if _, err := s.Load(); !errors.Is(err, ErrUncertain) {
					t.Fatal(err)
				}
				if err := s.Commit(2, policy(3)); !errors.Is(err, ErrUncertain) {
					t.Fatal(err)
				}
			}
			s.Close()
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			c, err := reopened.Load()
			if err != nil || c.Revision != expectedRevision {
				t.Fatalf("reopen=%d %v", c.Revision, err)
			}
			if err := reopened.Commit(c.Revision, policy(c.Revision+1)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRejectUnsafeCurrentAndDirectory(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "directory", "hardlink", "public", "corrupt", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTest(t)
			s.Close()
			name := filepath.Join(dir, currentName)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("absent", name)
			case "fifo":
				err = unix.Mkfifo(name, 0600)
			case "directory":
				err = os.Mkdir(name, 0700)
			case "hardlink":
				err = os.WriteFile(filepath.Join(dir, "other"), []byte("{}"), 0600)
				if err == nil {
					err = os.Link(filepath.Join(dir, "other"), name)
				}
			case "public":
				err = os.WriteFile(name, []byte("{}"), 0644)
			case "corrupt":
				err = os.WriteFile(name, []byte("{}"), 0600)
			case "oversize":
				err = os.WriteFile(name, []byte(strings.Repeat(" ", shareconfig.MaxInputBytes+1)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(dir); err == nil {
				opened.Close()
				t.Fatal("accepted unsafe current")
			}
			if _, err := os.Lstat(name); err != nil {
				t.Fatal("changed rejected evidence", err)
			}
		})
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(dir); !errors.Is(err, ErrUnsafe) {
		if s != nil {
			s.Close()
		}
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(alias + "/"); !errors.Is(err, ErrUnsafe) {
		if s != nil {
			s.Close()
		}
		t.Fatal(err)
	}
}

func TestPendingNeverPromoted(t *testing.T) {
	s, dir := openTest(t)
	if err := os.WriteFile(filepath.Join(dir, pendingName), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); !errors.Is(err, ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := reopened.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("outside", filepath.Join(dir, pendingName)); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Commit(1, policy(2)); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if c, err := reopened.Load(); err != nil || c.Revision != 1 {
		t.Fatalf("changed current: %v %v", c, err)
	}
}

// A process exit is not a power-loss test: it exercises abandoned state and
// kernel lock release while the host filesystem remains running.
func TestProcessExitRecovery(t *testing.T) {
	if dir := os.Getenv("PHANTOWD_STORE_EXIT_FIXTURE"); dir != "" {
		s, err := Open(dir)
		if err != nil {
			os.Exit(10)
		}
		if err := s.Commit(0, policy(1)); err != nil {
			os.Exit(11)
		}
		switch os.Getenv("PHANTOWD_STORE_EXIT_STAGE") {
		case "write":
			s.io.write = func(f *os.File, b []byte) (int, error) { f.Write(b[:8]); os.Exit(42); return 0, nil }
		case "file-sync":
			s.io.sync = func(f *os.File) error {
				if f.Sync() != nil {
					os.Exit(13)
				}
				os.Exit(42)
				return nil
			}
		case "rename":
			s.io.rename = func(int, string, int, string) error { os.Exit(42); return nil }
		case "directory-sync":
			s.io.syncDir = func(int) error { os.Exit(42); return nil }
		default:
			os.Exit(14)
		}
		s.Commit(1, policy(2))
		os.Exit(12)
	}
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestProcessExitRecovery$")
			cmd.Env = append(os.Environ(), "PHANTOWD_STORE_EXIT_FIXTURE="+dir, "PHANTOWD_STORE_EXIT_STAGE="+stage)
			err := cmd.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 42 {
				t.Fatalf("child=%v", err)
			}
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			want := uint64(1)
			if stage == "directory-sync" {
				want = 2
			}
			if c, err := s.Load(); err != nil || c.Revision != want {
				t.Fatalf("child current=%v %v", c, err)
			}
			if err := s.Commit(want, policy(want+1)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestZeroStoreRefusesUse(t *testing.T) {
	var s Store[shareconfig.Config]
	if _, err := s.Load(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidCodecRefusedBeforeOpeningDirectory(t *testing.T) {
	for _, mutate := range []func(*Codec[shareconfig.Config]){
		func(c *Codec[shareconfig.Config]) { c.CurrentName = "../outside" },
		func(c *Codec[shareconfig.Config]) { c.PendingName = "/outside" },
		func(c *Codec[shareconfig.Config]) { c.CurrentName = "." },
		func(c *Codec[shareconfig.Config]) { c.PendingName = c.CurrentName },
		func(c *Codec[shareconfig.Config]) { c.MaxBytes = 0 },
		func(c *Codec[shareconfig.Config]) { c.MaxBytes = 1<<20 + 1 },
		func(c *Codec[shareconfig.Config]) { c.Decode = nil },
		func(c *Codec[shareconfig.Config]) { c.Validate = nil },
		func(c *Codec[shareconfig.Config]) { c.Revision = nil },
	} {
		codec := shareCodec()
		mutate(&codec)
		if s, err := OpenWithCodec(t.TempDir(), codec); !errors.Is(err, ErrUnsafe) {
			if s != nil {
				s.Close()
			}
			t.Fatal(err)
		}
	}
}

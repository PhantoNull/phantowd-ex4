// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func readerFixture(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(fixtureDocument())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, currentName), data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return dir, f
}

func TestRegistryReaderOwnsDescriptorAndReturnsIndependentClaims(t *testing.T) {
	dir, borrowed := readerFixture(t)
	r, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	var before, after unix.Stat_t
	file := filepath.Join(dir, currentName)
	if unix.Stat(file, &before) != nil {
		t.Fatal("missing fixture")
	}
	s, err := r.Read(context.Background())
	d, claimErr := s.Claims()
	if err != nil || claimErr != nil || !reflect.DeepEqual(d, fixtureDocument()) {
		t.Fatal("protected claims lost", err, claimErr)
	}
	if unix.Stat(file, &after) != nil || !sameMetadata(before, after) || before.Atim != after.Atim {
		t.Fatal("reader altered registry metadata")
	}
	// A writer cannot enter while this reader retains the shared lock.
	writer, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("writer entered reader observation lifetime")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("reader leaked directory flock")
	}
	if _, err := r.Read(context.Background()); err != ErrObservation {
		t.Fatal("closed reader accepted")
	}
	if r.Close() != ErrObservation {
		t.Fatal("double close accepted")
	}
	// Snapshot remains point-in-time data, not a lifetime handle.
	if _, err := s.Claims(); err != nil {
		t.Fatal("closed reader invalidated immutable data")
	}
}

func TestRegistryReaderRejectsUnsafeInputsWithoutPartialSnapshot(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "corrupt", "oversized", "mode", "hardlink", "symlink", "fifo", "directory", "writer", "directory-mode", "foreign-file-owner", "foreign-directory-owner"} {
		t.Run(kind, func(t *testing.T) {
			dir, f := readerFixture(t)
			file := filepath.Join(dir, currentName)
			switch kind {
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(file, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(file, []byte(`{"revision":99}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(file, []byte(strings.Repeat(" ", MaxInputBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "symlink", "fifo", "directory":
				if err := os.Rename(file, filepath.Join(dir, "other")); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "symlink" {
					err = os.Symlink("other", file)
				} else if kind == "fifo" {
					err = unix.Mkfifo(file, 0600)
				} else {
					err = os.Mkdir(file, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "writer":
				if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
					t.Fatal("fixture lock failed")
				}
			case "directory-mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "foreign-file-owner", "foreign-directory-owner":
				if os.Geteuid() != 0 {
					t.Skip("ownership change requires disposable root test environment")
				}
				target := file
				if kind == "foreign-directory-owner" {
					target = dir
				}
				if err := os.Chown(target, 12345, -1); err != nil {
					t.Fatal(err)
				}
			}
			r, err := Open(f)
			if kind == "writer" || kind == "directory-mode" || kind == "foreign-directory-owner" {
				if r != nil || err != ErrObservation {
					t.Fatal("unsafe constructor accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.Read(context.Background())
			if err != ErrObservation || !reflect.DeepEqual(got, Snapshot{}) {
				t.Fatal("unsafe file yielded partial snapshot")
			}
		})
	}
}

func TestRegistryReaderRejectsActualMetadataRaces(t *testing.T) {
	for _, kind := range []string{"replace", "delete", "chmod", "hardlink", "directory-mode", "directory-entry", "rewrite", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			dir, f := readerFixture(t)
			r, err := Open(f)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			file := filepath.Join(dir, currentName)
			got, err := r.read(ctx, func() {
				var err error
				switch kind {
				case "replace":
					err = os.Rename(file, filepath.Join(dir, "old"))
					if err == nil {
						data, _ := json.Marshal(fixtureDocument())
						err = os.WriteFile(file, data, 0600)
					}
				case "delete":
					err = os.Remove(file)
				case "chmod":
					err = os.Chmod(file, 0644)
				case "hardlink":
					err = os.Link(file, filepath.Join(dir, "alias"))
				case "directory-mode":
					err = os.Chmod(dir, 0755)
				case "directory-entry":
					err = os.WriteFile(filepath.Join(dir, "unrelated"), []byte("fixture"), 0600)
				case "rewrite":
					err = os.WriteFile(file, []byte(`{}`), 0600)
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			if err != ErrObservation || !reflect.DeepEqual(got, Snapshot{}) {
				t.Fatal("race produced partial snapshot")
			}
		})
	}
}

func TestRegistryReaderInvalidLifecycleAndConcurrentReads(t *testing.T) {
	if _, err := Open(nil); err != ErrObservation {
		t.Fatal("nil descriptor accepted")
	}
	var nilReader *Reader
	if _, err := nilReader.Read(context.Background()); err != ErrObservation {
		t.Fatal("nil reader accepted")
	}
	if nilReader.Close() != ErrObservation {
		t.Fatal("nil reader close accepted")
	}
	_, f := readerFixture(t)
	r, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Read(nil); err != ErrObservation {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Read(ctx); err != ErrObservation {
		t.Fatal("cancelled context accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Read(context.Background()); err != nil {
				t.Error("serialized read failed", err)
			}
		}()
	}
	wg.Wait()
}

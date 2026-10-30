// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package admincredentials

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"golang.org/x/sys/unix"
)

func TestDirectoryGrantRetainsOriginalStoreAfterCallerCloseAndPathReplacement(t *testing.T) {
	base := t.TempDir()
	path, retired := filepath.Join(base, "admin"), filepath.Join(base, "retired")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	s, err := OpenDirectory(source)
	if err != nil {
		t.Fatal("inherited directory cannot use a no-follow pathname opener", err)
	}
	defer s.Close()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize("nas-admin", fixtureVerifier); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(1, replacementVerifier); err != nil {
		t.Fatal(err)
	}
	assertSnapshot(t, s, 2, replacementVerifier)
	replacement, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if _, err := replacement.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal("directory grant redirected writes into replacement path", err)
	}
	other, err := Open(retired)
	if !errors.Is(err, revisionstore.ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("original directory lock was not retained", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(retired)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertSnapshot(t, reopened, 2, replacementVerifier)
}

func TestDirectoryGrantPathOnlySourceUsesIndependentWriterLock(t *testing.T) {
	fd, err := unix.Open(privateDirectory(t), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	source := os.NewFile(uintptr(fd), "path-only-grant")
	defer source.Close()
	s, err := OpenDirectory(source)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other, err := OpenDirectory(source)
	if !errors.Is(err, revisionstore.ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("borrowed grant shared the writer's open-file-description lock", err)
	}
	if _, err := source.Stat(); err != nil {
		t.Fatal("refusal closed caller's grant", err)
	}
}

func TestDirectoryGrantRefusesInvalidSources(t *testing.T) {
	for _, kind := range []string{"nil", "closed", "regular", "mode"} {
		t.Run(kind, func(t *testing.T) {
			var source *os.File
			if kind != "nil" {
				path := privateDirectory(t)
				if kind == "regular" {
					path = filepath.Join(path, "file")
					if err := os.WriteFile(path, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "mode" {
					if err := os.Chmod(path, 0755); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				source, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if kind == "closed" {
					if err := source.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if s, err := OpenDirectory(source); !errors.Is(err, revisionstore.ErrUnsafe) || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("unsafe startup directory accepted", err)
			}
		})
	}
}

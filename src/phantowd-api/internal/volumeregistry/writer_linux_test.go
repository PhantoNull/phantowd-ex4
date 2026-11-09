// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

func TestExplicitRegistryClaimSurvivesWriterCloseAndProtectedRead(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	writer, err := OpenWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal("opening initialized or reset the registry", err)
	}
	initial := fixtureDocument()
	initial.Revision = 1
	if err := writer.Commit(0, initial); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(path, "volumes.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe persisted registry", info, err)
	}
	directory, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	reader, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := snapshot.Claims()
	if err != nil || !reflect.DeepEqual(got, initial) {
		t.Fatal("explicit identity did not survive reopen", got, err)
	}
}

func registryWriterFixture(t *testing.T) (*revisionstore.Store[Document], string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	writer, err := OpenWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	return writer, path
}

func TestRegistryWriterRefusesRetiredOrReassignedIdentityWithoutChangingEvidence(t *testing.T) {
	for _, kind := range []string{"remove", "rename", "rebind"} {
		t.Run(kind, func(t *testing.T) {
			writer, path := registryWriterFixture(t)
			initial := fixtureDocument()
			initial.Revision = 1
			if err := writer.Commit(0, initial); err != nil {
				t.Fatal(err)
			}
			pending := filepath.Join(path, ".volumes.pending")
			if err := os.WriteFile(pending, []byte("prior pending evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			stamps := map[string]os.FileInfo{}
			for _, name := range []string{"volumes.json", ".volumes.pending"} {
				var err error
				before[name], err = os.ReadFile(filepath.Join(path, name))
				if err != nil {
					t.Fatal(err)
				}
				stamps[name], err = os.Stat(filepath.Join(path, name))
				if err != nil {
					t.Fatal(err)
				}
			}
			next := fixtureDocument()
			next.Revision = 2
			switch kind {
			case "remove":
				next.Volumes = next.Volumes[:0]
			case "rename":
				next.Volumes[0].ID = "renamed"
			case "rebind":
				next.Volumes[0].FilesystemUUID = "11111111-2222-3333-4444-555555555555"
			}
			if err := writer.Commit(1, next); !errors.Is(err, revisionstore.ErrInvalid) {
				t.Fatal("retained identity changed", err)
			}
			for name, want := range before {
				got, readErr := os.ReadFile(filepath.Join(path, name))
				stamp, statErr := os.Stat(filepath.Join(path, name))
				if readErr != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(stamps[name], stamp) {
					t.Fatal("refusal changed original evidence", name, readErr, statErr)
				}
			}
			got, err := writer.Load()
			if err != nil || !reflect.DeepEqual(got, initial) {
				t.Fatal("refusal changed claims", got, err)
			}
		})
	}
}

func TestRegistryWriterAppendsWithCASAndExcludesProtectedReaders(t *testing.T) {
	writer, path := registryWriterFixture(t)
	initial := fixtureDocument()
	initial.Revision = 1
	if err := writer.Commit(0, initial); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if reader, err := Open(directory); err == nil || reader != nil {
		if reader != nil {
			reader.Close()
		}
		t.Fatal("reader overlapped writer")
	}
	if other, err := OpenWriter(directory); !errors.Is(err, revisionstore.ErrBusy) || other != nil {
		if other != nil {
			other.Close()
		}
		t.Fatal("second writer admitted", err)
	}
	next := fixtureDocument()
	next.Revision = 2
	next.Volumes = append(next.Volumes, shareconfig.Volume{ID: "explicit-second", FilesystemUUID: "11111111-2222-3333-4444-555555555555"})
	outcomes := make(chan error, 2)
	for range 2 {
		go func() { outcomes <- writer.Commit(1, next) }()
	}
	successes := 0
	for range 2 {
		if err := <-outcomes; err == nil {
			successes++
		} else if !errors.Is(err, revisionstore.ErrConflict) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("stale registration committed more than once", successes)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := snapshot.Claims()
	if err != nil || !reflect.DeepEqual(claims, next) {
		t.Fatal("append or original identity lost", claims, err)
	}
	if other, err := OpenWriter(directory); !errors.Is(err, revisionstore.ErrBusy) || other != nil {
		if other != nil {
			other.Close()
		}
		t.Fatal("writer overlapped retained reader", err)
	}
	if err := reader.Recheck(context.Background(), snapshot); err != nil {
		t.Fatal("refused writer disturbed protected observation", err)
	}
}

func TestRegistryWriterRefusesCorruptOrUnsafeStateWithoutReset(t *testing.T) {
	if writer, err := OpenWriter(nil); err == nil || writer != nil {
		t.Fatal("nil directory admitted")
	}
	for _, kind := range []string{"corrupt-current", "linked-current", "unsafe-directory"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(path, "volumes.json")
			original := []byte("preserve invalid evidence")
			if kind != "corrupt-current" {
				var encodeErr error
				original, encodeErr = json.Marshal(fixtureDocument())
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
			}
			target := current
			if kind == "linked-current" {
				target = filepath.Join(path, "original")
			}
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "linked-current" {
				if err := os.Symlink(target, current); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unsafe-directory" {
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			directory, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if writer, err := OpenWriter(directory); err == nil || writer != nil {
				if writer != nil {
					writer.Close()
				}
				t.Fatal("unsafe state silently admitted")
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("constructor reset evidence", err)
			}
			if _, err := os.Lstat(filepath.Join(path, ".volumes.pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("constructor created pending state", err)
			}
		})
	}
}

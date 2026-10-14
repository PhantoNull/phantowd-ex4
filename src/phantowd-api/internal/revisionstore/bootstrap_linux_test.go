//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"

	"golang.org/x/sys/unix"
)

func TestBootstrapEmptyDirectoryObservationDoesNotInitializeOrChangeMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var before, after unix.Stat_t
	if err := unix.Stat(dir, &before); err != nil {
		t.Fatal(err)
	}
	got, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec())
	if err != nil || got.Kind != BootstrapEmptyDirectory || got.Revision != 0 {
		t.Fatal("empty directory not observed", got, err)
	}
	fdBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if observed, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec()); err != nil || observed != got {
			t.Fatal("repeat read changed observation", observed, err)
		}
	}
	fdAfter, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(fdBefore) != len(fdAfter) {
		t.Fatal("observation accumulated descriptors", len(fdBefore), len(fdAfter), err)
	}
	if err := unix.Stat(dir, &after); err != nil || before != after {
		t.Fatal("read-only observation changed directory metadata", before, after, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("observation initialized state", entries, err)
	}
	// No token/lease or whole-NAS pristine conclusion is returned. A separate
	// explicit writer still sees missing current state, never an empty policy.
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); err != ErrNotInitialized {
		t.Fatal("observation initialized policy", err)
	}
}

func TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprint(initialized), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if initialized {
				s, err := OpenWithCodec(dir, nasKillCodec())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Commit(0, nasKillPolicy(1)); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			pending := []byte("interrupted, not valid JSON")
			name := filepath.Join(dir, nasKillCodec().PendingName)
			if err := os.WriteFile(name, pending, 0600); err != nil {
				t.Fatal(err)
			}
			var before, after unix.Stat_t
			if err := unix.Stat(name, &before); err != nil {
				t.Fatal(err)
			}
			got, err := ObserveBootstrapWithCodec(context.Background(), dir, nasKillCodec())
			if err != nil || got.Kind != "pending-evidence" || got.Revision != 0 {
				t.Fatal("pending evidence not distinguished", got, err)
			}
			if err := unix.Stat(name, &after); err != nil || before != after {
				t.Fatal("observation touched pending metadata", err)
			}
			if data, err := os.ReadFile(name); err != nil || !reflect.DeepEqual(data, pending) {
				t.Fatal("pending changed", err)
			}
			s, err := OpenWithCodec(dir, nasKillCodec())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			gotPolicy, loadErr := s.Load()
			if initialized {
				if loadErr != nil || !reflect.DeepEqual(gotPolicy, nasKillPolicy(1)) {
					t.Fatal("observation changed confirmed policy", gotPolicy, loadErr)
				}
			} else if !errors.Is(loadErr, ErrNotInitialized) {
				t.Fatal("pending initialized current state", loadErr)
			}
		})
	}
}

func TestBootstrapValidCurrentPolicyObservationDoesNotChangeFilesOrReturnPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, nasKillPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, nasKillCodec().CurrentName)
	var beforeFile, afterFile, beforeDir, afterDir unix.Stat_t
	if unix.Stat(path, &beforeFile) != nil || unix.Stat(dir, &beforeDir) != nil {
		t.Fatal("original metadata")
	}
	got, err := ObserveBootstrapWithCodec(context.Background(), dir, nasKillCodec())
	if err != nil || got != (BootstrapObservation{Kind: "valid-current-policy", Revision: 1}) {
		t.Fatal("valid current revision not observed", got, err)
	}
	if unix.Stat(path, &afterFile) != nil || unix.Stat(dir, &afterDir) != nil || beforeFile != afterFile || beforeDir != afterDir {
		t.Fatal("observation modified original metadata")
	}
	s, err = OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if loaded, err := s.Load(); err != nil || !reflect.DeepEqual(loaded, nasKillPolicy(1)) {
		t.Fatal("confirmed policy changed", loaded, err)
	}
}

func TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset(t *testing.T) {
	for _, data := range []string{"", "broken JSON", "{}", `{"format":"other","schema_version":9,"revision":8}`} {
		t.Run(fmt.Sprint(len(data)), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, nasKillCodec().CurrentName)
			if err := os.WriteFile(name, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := ObserveBootstrapWithCodec(context.Background(), dir, nasKillCodec())
			if err != nil || got.Kind != "invalid-or-unsupported-policy" || got.Revision != 0 {
				t.Fatal("invalid state treated as usable or missing", got, err)
			}
			if after, err := os.ReadFile(name); err != nil || string(after) != data {
				t.Fatal("invalid evidence reset", err)
			}
		})
	}
}

func TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed(t *testing.T) {
	for _, count := range []int{1, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := OpenWithCodec(dir, nasKillCodec())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Commit(0, nasKillPolicy(1)); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("legacy-%02d.json", i)), []byte("legacy evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ObserveBootstrapWithCodec(context.Background(), dir, nasKillCodec())
			if err != nil || got.Kind != "unrecognized-entries" || got.Revision != 0 {
				t.Fatal("unknown evidence admitted or omitted", got, err)
			}
			for i := 0; i < count; i++ {
				if data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("legacy-%02d.json", i))); err != nil || string(data) != "legacy evidence" {
					t.Fatal("legacy evidence changed", err)
				}
			}
		})
	}
}

func TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData(t *testing.T) {
	for _, role := range []string{currentName, pendingName} {
		for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "permissions"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(dir, role)
				switch kind {
				case "symlink", "hardlink":
					other := filepath.Join(t.TempDir(), "foreign")
					if err := os.WriteFile(other, []byte("not a policy"), 0600); err != nil {
						t.Fatal(err)
					}
					var err error
					if kind == "symlink" {
						err = os.Symlink(other, name)
					} else {
						err = os.Link(other, name)
					}
					if err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(name, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(name, 0700); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.WriteFile(name, []byte("wrong permissions"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				got, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec())
				if !errors.Is(err, ErrUnsafe) || got != (BootstrapObservation{}) {
					t.Fatal("unsafe object produced observation", got, err)
				}
				if _, err := os.Lstat(name); err != nil {
					t.Fatal("refusal deleted evidence", err)
				}
			})
		}
	}
}

func TestBootstrapRefusesBusyCanceledMissingAndOversizedStateWithoutMutation(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec()); !errors.Is(err, ErrBusy) || got != (BootstrapObservation{}) {
		t.Fatal("writer lock bypassed", got, err)
	}
	if got, err := s.Load(); err != nil || got.Revision != 1 {
		t.Fatal("observation affected lock owner", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := ObserveBootstrapWithCodec(ctx, dir, shareCodec()); !errors.Is(err, context.Canceled) || got != (BootstrapObservation{}) {
		t.Fatal("canceled observation acquired state", got, err)
	}
	if got, err := ObserveBootstrapWithCodec(nil, dir, shareCodec()); !errors.Is(err, ErrInvalid) || got != (BootstrapObservation{}) {
		t.Fatal("nil context admitted", got, err)
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), filepath.Join(dir, "missing"), shareCodec()); !errors.Is(err, ErrIO) || got != (BootstrapObservation{}) {
		t.Fatal("unavailable directory treated as empty", got, err)
	}
	if err := os.Truncate(filepath.Join(dir, currentName), int64(shareCodec().MaxBytes)+1); err != nil {
		t.Fatal(err)
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec()); !errors.Is(err, ErrUnsafe) || got != (BootstrapObservation{}) {
		t.Fatal("oversized policy read", got, err)
	}
}

func TestBootstrapWritableOpenDuringDecodeRefusesEvenWithUnchangedMetadata(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, currentName)
	codec := shareCodec()
	decode := codec.Decode
	codec.Decode = func(r io.Reader) (shareconfig.Config, error) {
		doc, err := decode(r)
		var before, after unix.Stat_t
		if unix.Stat(name, &before) != nil {
			t.Fatal("original metadata")
		}
		w, openErr := os.OpenFile(name, os.O_WRONLY, 0)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if closeErr := w.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if unix.Stat(name, &after) != nil || before != after {
			t.Fatal("write-capable open changed metadata")
		}
		return doc, err
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), dir, codec); !errors.Is(err, ErrReview) || got != (BootstrapObservation{}) {
		t.Fatal("writable lifetime uncertainty admitted", got, err)
	}
}

func TestBootstrapCancellationDuringDecodeReturnsNoObservation(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codec := shareCodec()
	decode := codec.Decode
	codec.Decode = func(r io.Reader) (shareconfig.Config, error) { doc, err := decode(r); cancel(); return doc, err }
	if got, err := ObserveBootstrapWithCodec(ctx, dir, codec); !errors.Is(err, context.Canceled) || got != (BootstrapObservation{}) {
		t.Fatal("canceled decode returned observation", got, err)
	}
}

func TestBootstrapRefusesInvalidCodecDirectoryAndMissingRootWithoutInitialization(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		codec := shareCodec()
		switch i {
		case 0:
			codec.CurrentName = "../escape"
		case 1:
			codec.PendingName = codec.CurrentName
		case 2:
			codec.Decode = nil
		case 3:
			codec.MaxBytes = 0
		case 4:
			codec.MaxBytes = (1 << 20) + 1
		}
		if got, err := ObserveBootstrapWithCodec(context.Background(), dir, codec); !errors.Is(err, ErrUnsafe) || got != (BootstrapObservation{}) {
			t.Fatal("invalid trusted declaration admitted", got, err)
		}
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), "relative", shareCodec()); !errors.Is(err, ErrUnsafe) || got != (BootstrapObservation{}) {
		t.Fatal("relative directory admitted", got, err)
	}
	missing := filepath.Join(dir, "missing")
	if got, err := ObserveBootstrapWithCodec(context.Background(), missing, shareCodec()); !errors.Is(err, ErrIO) || got != (BootstrapObservation{}) {
		t.Fatal("missing root treated as initialized", got, err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing root was created", err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := ObserveBootstrapWithCodec(context.Background(), dir, shareCodec()); !errors.Is(err, ErrUnsafe) || got != (BootstrapObservation{}) {
		t.Fatal("unprotected directory admitted", got, err)
	}
}

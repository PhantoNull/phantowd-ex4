// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const killFixtureEnv = "PHANTOWD_BUNDLE_KILL_FIXTURE"
const killStageEnv = "PHANTOWD_BUNDLE_KILL_STAGE"

func killCodec() Codec[fileservice.Config] {
	return Codec[fileservice.Config]{CurrentName: "file-services.json", PendingName: ".file-services.pending",
		MaxBytes: fileservice.MaxConfigBytes, Decode: fileservice.DecodeConfig, Validate: fileservice.Config.Validate,
		Revision: func(c fileservice.Config) uint64 { return c.Revision }}
}

// Each revision changes both protocol policies, not only their counters.
func killPolicy(revision uint64) fileservice.Config {
	access, path := "ro", "old-books"
	if revision == 2 {
		access, path = "rw", "new-books"
	}
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
			Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
			Users:   []shareconfig.User{{ID: "reader", Name: "reader"}},
			Shares: []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: path,
				Grants: []shareconfig.Grant{{UserID: "reader", Access: access}}}}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: path,
				Clients: []nfsconfig.Client{{Network: "192.0.2.10/32", Access: access, Squash: "all",
					AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}}}
}

// This helper exists only in the Go test binary. The gate retains the store,
// file (when still open) and directory lock without running defer/Close. The
// parent checks lock ownership and sends SIGKILL; stdin stays open until then.
func TestBundleKillWriterHelper(t *testing.T) {
	dir := os.Getenv(killFixtureEnv)
	if dir == "" {
		return
	}
	s, err := OpenWithCodec(dir, killCodec())
	if err != nil {
		t.Fatal(err)
	}
	gate := func() {
		if _, err := os.Stdout.Write([]byte{'K'}); err != nil {
			t.Fatal(err)
		}
		var token [1]byte
		_, err := io.ReadFull(os.Stdin, token[:])
		t.Fatalf("interruption gate unexpectedly returned: %v", err)
	}
	switch os.Getenv(killStageEnv) {
	case "partial-write":
		s.io.write = func(f *os.File, b []byte) (int, error) {
			if n, err := f.Write(b[:8]); n != 8 || err != nil {
				t.Fatalf("partial write: %d %v", n, err)
			}
			gate()
			return 0, nil
		}
	case "full-write":
		s.io.write = func(f *os.File, b []byte) (int, error) {
			n, err := f.Write(b)
			if n != len(b) || err != nil {
				t.Fatalf("full write: %d %v", n, err)
			}
			gate()
			return n, err
		}
	case "file-sync":
		s.io.sync = func(f *os.File) error {
			if err := f.Sync(); err != nil {
				t.Fatal(err)
			}
			gate()
			return nil
		}
	case "file-close":
		s.io.close = func(f *os.File) error {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			gate()
			return nil
		}
	case "before-rename", "after-rename":
		s.io.rename = func(a int, b string, c int, d string) error {
			if os.Getenv(killStageEnv) == "before-rename" {
				gate()
			}
			if err := unix.Renameat(a, b, c, d); err != nil {
				t.Fatal(err)
			}
			gate()
			return nil
		}
	case "directory-sync":
		s.io.syncDir = func(fd int) error {
			if err := unix.Fsync(fd); err != nil {
				t.Fatal(err)
			}
			gate()
			return nil
		}
	default:
		t.Fatal("unknown interruption stage")
	}
	t.Fatalf("commit unexpectedly returned: %v", s.Commit(1, killPolicy(2)))
}

func TestBundleSIGKILLRecovery(t *testing.T) {
	for _, stage := range []string{"partial-write", "full-write", "file-sync", "file-close", "before-rename", "after-rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := OpenWithCodec(dir, killCodec())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Commit(0, killPolicy(1)); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBundleKillWriterHelper$")
			cmd.Env = append(os.Environ(), killFixtureEnv+"="+dir, killStageEnv+"="+stage)
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			in, err := cmd.StdinPipe()
			if err != nil {
				out.Close()
				t.Fatal(err)
			}
			defer in.Close()
			if err := cmd.Start(); err != nil {
				out.Close()
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			var marker [1]byte
			if _, err := io.ReadFull(out, marker[:]); err != nil || marker[0] != 'K' {
				t.Fatalf("writer did not reach gate: %q %v", marker, err)
			}
			if other, err := OpenWithCodec(dir, killCodec()); !errors.Is(err, ErrBusy) {
				if other != nil {
					other.Close()
				}
				t.Fatalf("live child lost lock: %v", err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatalf("writer wait: %v", err)
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || ctx.Err() != nil {
				t.Fatalf("writer was not deliberately killed: %v %v", status, ctx.Err())
			}

			want := uint64(1)
			published := stage == "after-rename" || stage == "directory-sync"
			if published {
				want = 2
			}
			pendingPath := filepath.Join(dir, killCodec().PendingName)
			pending, pendingErr := os.ReadFile(pendingPath)
			nextBytes, err := json.Marshal(killPolicy(2))
			if err != nil {
				t.Fatal(err)
			}
			if published {
				if !errors.Is(pendingErr, os.ErrNotExist) {
					t.Fatal("published pending still exists", pendingErr)
				}
			} else {
				if stage == "partial-write" {
					nextBytes = nextBytes[:8]
				}
				if pendingErr != nil || !bytes.Equal(pending, nextBytes) {
					t.Fatal("abandoned pending differs from gate", pendingErr)
				}
			}
			s, err = OpenWithCodec(dir, killCodec())
			if err != nil {
				t.Fatal("kernel did not release child lock", err)
			}
			defer s.Close()
			if got, err := s.Load(); err != nil || !reflect.DeepEqual(got, killPolicy(want)) {
				t.Fatal("split, empty or unexpected committed policy", got, err)
			}
			if !published {
				if data, err := os.ReadFile(pendingPath); err != nil || !bytes.Equal(data, pending) {
					t.Fatal("reopen/load changed pending evidence", err)
				}
			}
			if err := s.Commit(want-1, killPolicy(want)); !errors.Is(err, ErrConflict) {
				t.Fatal("stale retry accepted", err)
			}
			if err := s.Commit(want, killPolicy(want+1)); err != nil {
				t.Fatal("explicit next commit failed", err)
			}
			if got, err := s.Load(); err != nil || !reflect.DeepEqual(got, killPolicy(want+1)) {
				t.Fatal("next commit split policy", got, err)
			}
			if _, err := os.Lstat(pendingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("successful commit left pending", err)
			}
		})
	}
}

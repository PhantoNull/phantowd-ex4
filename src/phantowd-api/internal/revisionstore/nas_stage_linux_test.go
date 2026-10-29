//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"golang.org/x/sys/unix"
)

func TestNASEvidenceStagePublishesExactBytesWithoutRemovingOtherRoles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	old := []byte("exact previous bytes\n")
	if err := os.WriteFile(filepath.Join(dir, "nas-services.json"), old, 0600); err != nil {
		t.Fatal(err)
	}
	data := []byte("exact base bytes\n")
	if err := stageNASEvidenceRole(context.Background(), root, ".nas-services.base", data, systemOps()); err != nil {
		t.Fatal(err)
	}
	for role, want := range map[string][]byte{"nas-services.json": old, ".nas-services.base": data} {
		got, err := os.ReadFile(filepath.Join(dir, role))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("role changed or was not published", role, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, ".nas-services.pending")); !os.IsNotExist(err) {
		t.Fatal("pending remains after verified publication", err)
	}
	for _, role := range []string{"nas-services.json", ".nas-services.intent", ".nas-services.receipt", ".nas-services.base"} {
		if err := stageNASEvidenceRole(context.Background(), root, role, data, systemOps()); err != nil {
			t.Fatal(role, err)
		}
		if got, err := os.ReadFile(filepath.Join(dir, role)); err != nil || !bytes.Equal(got, data) {
			t.Fatal("publication differs", role, err)
		}
	}
}

func TestNASEvidenceStageRefusesUnsafeDestinationBeforeEffects(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "hardlink", "permissions", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			path := filepath.Join(dir, ".nas-services.base")
			switch kind {
			case "symlink":
				err = os.Symlink("nas-services.json", path)
			case "directory":
				err = os.Mkdir(path, 0700)
			default:
				err = os.WriteFile(path, []byte("retained evidence"), 0600)
				if err == nil && kind == "hardlink" {
					err = os.Link(path, filepath.Join(dir, "other"))
				}
				if err == nil && kind == "permissions" {
					err = os.Chmod(path, 0644)
				}
				if err == nil && kind == "oversized" {
					err = os.Truncate(path, naspolicy.MaxInputBytes+1)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := stageNASEvidenceRole(context.Background(), root, ".nas-services.base", []byte("new"), systemOps()); !errors.Is(err, ErrUnsafe) {
				t.Fatal("unsafe destination accepted", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, ".nas-services.pending")); !os.IsNotExist(err) {
				t.Fatal("refusal created pending", err)
			}
		})
	}
}

func TestNASEvidenceStagePreservesPendingAndRefusesInvalidInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stageNASEvidenceRole(ctx, root, "nas-services.json", []byte("new"), systemOps()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, role := range []string{"nas-evidence.json", ".nas-services.pending", "../other", "unknown"} {
		if err := stageNASEvidenceRole(context.Background(), root, role, []byte("new"), systemOps()); !errors.Is(err, ErrInvalid) {
			t.Fatal(role, err)
		}
	}
	if names, err := os.ReadDir(dir); err != nil || len(names) != 0 {
		t.Fatal("invalid input had effects", err)
	}
	for _, data := range [][]byte{nil, make([]byte, naspolicy.MaxInputBytes+1)} {
		if err := stageNASEvidenceRole(context.Background(), root, "nas-services.json", data, systemOps()); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid payload accepted", err)
		}
	}
	if err := stageNASEvidenceRole(context.Background(), root, ".nas-services.intent", make([]byte, 4097), systemOps()); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized record accepted", err)
	}
	path := filepath.Join(dir, ".nas-services.pending")
	if err := os.WriteFile(path, []byte("original pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageNASEvidenceRole(context.Background(), root, "nas-services.json", []byte("new"), systemOps()); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original pending" {
		t.Fatal("pending evidence changed", err)
	}
}

func TestNASEvidenceStageUncertainBoundariesPreserveEvidence(t *testing.T) {
	for _, boundary := range []string{"write", "short-write", "sync", "close", "rename", "directory-sync", "readback", "destination-drift", "cancel-write", "cancel-sync", "cancel-close", "cancel-rename", "cancel-directory-sync"} {
		t.Run(boundary, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".nas-services.base")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops, calls, closes := systemOps(), []string{}, 0
			fault := func(phase string) error {
				calls = append(calls, phase)
				if boundary == "cancel-"+phase {
					cancel()
				}
				if boundary == phase {
					return unix.ENOSPC
				}
				return nil
			}
			ops.write = func(f *os.File, b []byte) (int, error) {
				if err := fault("write"); err != nil {
					return 0, err
				}
				if boundary == "short-write" {
					return f.Write(b[:1])
				}
				return f.Write(b)
			}
			ops.sync = func(f *os.File) error {
				if err := fault("sync"); err != nil {
					return err
				}
				return f.Sync()
			}
			ops.close = func(f *os.File) error {
				closes++
				err := f.Close()
				if boundary == "destination-drift" {
					if err := os.WriteFile(path, []byte("changed evidence"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return errors.Join(err, fault("close"))
			}
			ops.rename = func(a int, x string, b int, y string) error {
				if err := fault("rename"); err != nil {
					return err
				}
				return unix.Renameat(a, x, b, y)
			}
			ops.syncDir = func(fd int) error {
				if err := fault("directory-sync"); err != nil {
					return err
				}
				if boundary == "readback" {
					if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return unix.Fsync(fd)
			}
			if err := stageNASEvidenceRole(ctx, root, ".nas-services.base", []byte("new"), ops); !errors.Is(err, ErrReview) {
				t.Fatal("uncertain step reported success", err)
			}
			if closes != 1 {
				t.Fatal("close was omitted or retried", closes)
			}
			published := false
			for _, call := range calls {
				if call == "directory-sync" {
					published = true
				}
			}
			if boundary == "cancel-rename" {
				published = true
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !published && boundary != "destination-drift" && string(got) != "old" {
				t.Fatal("old evidence overwritten before publication")
			}
			_, pendingErr := os.Lstat(filepath.Join(dir, ".nas-services.pending"))
			if !published && pendingErr != nil {
				t.Fatal("failed staging evidence lost", pendingErr)
			}
			if published && !os.IsNotExist(pendingErr) {
				t.Fatal("unexpected pending after rename", pendingErr)
			}
			other, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
				t.Fatal("original authority released", err)
			}
		})
	}
}

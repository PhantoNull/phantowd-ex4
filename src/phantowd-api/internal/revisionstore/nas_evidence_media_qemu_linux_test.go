//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

var nasEvidenceMediaRoles = []string{
	"nas-evidence.json", "nas-services.json", ".nas-services.pending",
	".nas-services.intent", ".nas-services.receipt", ".nas-services.base",
}

func nasEvidenceMediaRole(t *testing.T, role string) (string, string, []byte) {
	t.Helper()
	dir := nasEvidenceFixture(t)
	path := filepath.Join(dir, role)
	if role == ".nas-services.pending" {
		if err := os.WriteFile(path, []byte("metadata-only evidence"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return dir, path, data
}

func requireNASEvidenceUnsafeMedia(t *testing.T, dir string, restore func() error) {
	t.Helper()
	a, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Error("fixture observer close", err)
		}
	}()
	got, err := a.Observe(context.Background())
	if !errors.Is(err, ErrReview) || !errors.Is(err, ErrUnsafe) || got != (NASEvidenceObservation{}) {
		t.Fatal("unsafe role returned partial or usable observation", got, err)
	}
	if err := restore(); err != nil {
		t.Fatal("fixture input restoration", err)
	}
	requireNASEvidenceReview(t, a, dir)
}

func TestNASEvidenceMediaForeignOwner(t *testing.T) {
	requireRevisionMediaQEMU(t) // ARM Versatile, fixed generated ext4, root only.
	t.Run("container", func(t *testing.T) {
		dir := nasEvidenceFixture(t)
		if err := os.Chown(dir, 65534, -1); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chown(dir, 0, -1); err != nil {
				t.Error("restore fixture owner", err)
			}
		}()
		a, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation)
		if a != nil {
			a.Close()
			t.Fatal("foreign container yielded authority", err)
		}
		if !errors.Is(err, ErrUnsafe) {
			t.Fatal("foreign container not refused as unsafe", err)
		}
	})
	for _, role := range nasEvidenceMediaRoles {
		t.Run(role, func(t *testing.T) {
			dir, path, data := nasEvidenceMediaRole(t, role)
			if err := os.Chown(path, 65534, -1); err != nil {
				t.Fatal(err)
			}
			restore := func() error { return os.Chown(path, 0, -1) }
			t.Cleanup(func() {
				if err := restore(); err != nil {
					t.Error("fixture owner cleanup", err)
				}
			})
			requireNASEvidenceUnsafeMedia(t, dir, restore)
			if after, err := os.ReadFile(path); err != nil || string(after) != string(data) {
				t.Fatal("reader altered original role bytes", err)
			}
		})
	}
}

func TestNASEvidenceMediaMountCrossings(t *testing.T) {
	requireRevisionMediaQEMU(t)
	for _, kind := range []string{"same-dev", "other-dev"} {
		for _, role := range nasEvidenceMediaRoles {
			if kind == "same-dev" && role == ".nas-services.pending" {
				continue // Pending presence is review; its data is never opened.
			}
			t.Run(kind+"-"+role, func(t *testing.T) {
				dir, path, data := nasEvidenceMediaRole(t, role)
				outside := t.TempDir()
				if kind == "other-dev" {
					if err := unix.Mount("tmpfs", outside, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=1m,mode=0700"); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := unix.Unmount(outside, 0); err != nil {
							t.Error("fixture tmpfs unmount", err)
						}
					})
				}
				source := filepath.Join(outside, "role-copy")
				if err := os.WriteFile(source, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mount(source, path, "", unix.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				mounted := true
				restore := func() error {
					if !mounted {
						return nil
					}
					if err := unix.Unmount(path, 0); err != nil {
						return err
					}
					mounted = false
					return nil
				}
				t.Cleanup(func() {
					if err := restore(); err != nil {
						t.Error("fixture bind unmount", err)
					}
				})
				var root, bound, original unix.Stat_t
				if unix.Stat(dir, &root) != nil || unix.Stat(path, &bound) != nil || unix.Stat(source, &original) != nil ||
					bound.Dev != original.Dev || bound.Ino != original.Ino || bound.Mode != unix.S_IFREG|0600 || bound.Uid != 0 || bound.Nlink != 1 ||
					(kind == "same-dev") != (bound.Dev == root.Dev) {
					t.Fatal("requested real bind/device relation not established")
				}
				// Same-dev cases pass the metadata device check: the confined open
				// must still reject traversal into the other mount via NO_XDEV.
				requireNASEvidenceUnsafeMedia(t, dir, restore)
				if after, err := os.ReadFile(path); err != nil || string(after) != string(data) {
					t.Fatal("reader altered covered original role bytes", err)
				}
			})
		}
	}
}

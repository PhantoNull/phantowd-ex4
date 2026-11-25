// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenFromDirectoryRetainsIndependentDescription(t *testing.T) {
	dir := provision(t)
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	borrowed := os.NewFile(uintptr(fd), "approved-identity-state")
	t.Cleanup(func() { _ = borrowed.Close() })
	inventory := newModel().dependencies().inventory
	owner, err := OpenFromDirectory(borrowed, inventory)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if other, err := OpenFromDirectory(borrowed, inventory); other != nil || !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("same descriptor bypassed the owner lock: %v", err)
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	registry, journals, err := owner.Snapshot(context.Background())
	if err != nil || registry.Revision != 1 || len(journals) != 0 {
		t.Fatalf("closing the borrowed descriptor changed the retained state: %v", err)
	}
}

func TestOpenFromDirectoryRejectsChangedRoles(t *testing.T) {
	for _, role := range []string{"registry", "operations"} {
		t.Run(role, func(t *testing.T) {
			dir := provision(t)
			root, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			inventory := newModel().dependencies().inventory
			owner, err := OpenFromDirectory(root, inventory)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			path := filepath.Join(dir, role)
			original := path + ".original"
			if err := os.Rename(path, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if _, _, err := owner.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("replacement role accepted: %v", err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(original, path); err != nil {
				t.Fatal(err)
			}
			if _, _, err := owner.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("restored role cleared review: %v", err)
			}
		})
	}
}

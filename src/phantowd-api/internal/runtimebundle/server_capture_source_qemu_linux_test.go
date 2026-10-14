//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerCaptureSourceBindingRejectsIdenticalForeignLeaf(t *testing.T) {
	rootName := t.TempDir()
	name := filepath.Join(rootName, "capture-read")
	if err := os.WriteFile(name, []byte("data"), 0444); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootName)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	original, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	var initial unix.Stat_t
	if unix.Fstat(int(original.Fd()), &initial) != nil {
		t.Fatal("original stat")
	}
	if err := recheckCaptureSourceQEMU(context.Background(), root, original, initial); err != nil {
		t.Fatal("original named object refused", err)
	}
	for _, kind := range []string{"identical-copy", "symlink", "missing"} {
		t.Run(kind, func(t *testing.T) {
			foreignName := t.TempDir()
			leaf := filepath.Join(foreignName, "capture-read")
			switch kind {
			case "identical-copy":
				if err := os.WriteFile(leaf, []byte("data"), 0444); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(name, leaf); err != nil {
					t.Fatal(err)
				}
			}
			foreign, err := os.Open(foreignName)
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			if err := recheckCaptureSourceQEMU(context.Background(), foreign, original, initial); !errors.Is(err, ErrMismatch) {
				t.Fatal("foreign named object admitted", kind, err)
			}
			var held unix.Stat_t
			if unix.Fstat(int(original.Fd()), &held) != nil || !samePendingObjectQEMU(initial, held) {
				t.Fatal("original changed during refusal")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recheckCaptureSourceQEMU(ctx, root, original, initial); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation lost cause", err)
	}
}

func TestServerCaptureShareBindingRejectsReplacedParentWithoutAdoptingIt(t *testing.T) {
	anchorName := t.TempDir()
	rootName := filepath.Join(anchorName, "run", "observer-readonly")
	if err := os.MkdirAll(rootName, 0755); err != nil {
		t.Fatal(err)
	}
	anchor, err := os.Open(anchorName)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	root, err := os.Open(rootName)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var initial unix.Statx_t
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if err := unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &initial); err != nil {
		t.Fatal("original root identity unavailable", err)
	}
	if initial.Mask&required != required {
		// A host kernel without unique mount IDs cannot qualify the positive
		// binding. Verify refusal here; the pinned ARM guest must run, not skip,
		// the real replacement/symlink/missing/restoration controls below.
		expected := serverObserverRootIdentityQEMU{initial.Dev_major, initial.Dev_minor, initial.Ino, 1}
		if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); !errors.Is(err, ErrMismatch) {
			t.Fatal("incomplete kernel identity admitted", err)
		}
		t.Skip("unique mount IDs unavailable; positive controls require pinned guest")
	}
	expected := serverObserverRootIdentityQEMU{initial.Dev_major, initial.Dev_minor, initial.Ino, initial.Mnt_id}
	if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); err != nil {
		t.Fatal("original share binding refused", err)
	}
	if err := os.Rename(rootName, rootName+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootName, 0755); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); !errors.Is(err, ErrMismatch) {
			t.Fatal("replacement share adopted", err)
		}
		if _, err := root.Stat(); err != nil {
			t.Fatal("original share lost", err)
		}
	}
	if err := os.Remove(rootName); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rootName+"-held", rootName); err != nil {
		t.Fatal(err)
	}
	if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); !errors.Is(err, ErrMismatch) {
		t.Fatal("share symlink admitted", err)
	}
	if err := os.Remove(rootName); err != nil {
		t.Fatal(err)
	}
	if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); !errors.Is(err, ErrMismatch) {
		t.Fatal("missing share admitted", err)
	}
	if err := os.Rename(rootName+"-held", rootName); err != nil {
		t.Fatal(err)
	}
	if err := recheckCaptureShareBindingQEMU(context.Background(), anchor, root, expected); err != nil {
		t.Fatal("restored metadata refused", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recheckCaptureShareBindingQEMU(ctx, anchor, root, expected); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

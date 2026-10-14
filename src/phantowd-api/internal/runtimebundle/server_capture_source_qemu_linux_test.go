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

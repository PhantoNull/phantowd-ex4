//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

func TestQEMUNFSRebootKnownPolicy(t *testing.T) {
	ctx, root := context.Background(), t.TempDir()
	for _, phase := range []string{"unknown", "verify"} {
		b := &qemuNFSReboot{}
		if err := b.policy(ctx, root, phase); err == nil {
			t.Fatal("uninitialized or unknown fixture admitted", phase)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("refusal initialized state", entries, err)
		}
	}
	for i, phase := range []string{"seed", "verify"} {
		b := &qemuNFSReboot{}
		if err := b.policy(ctx, root, phase); err != nil {
			t.Fatal(phase, err)
		}
		if b.rev != uint64(i+1) {
			t.Fatal("wrong independently expected revision", b.rev)
		}
		if err := b.owner.Commit(ctx, b.rev, qemuNFSRebootPolicy(b.rev+1)); !errors.Is(err, naspolicystore.ErrBusy) {
			t.Fatal("live policy claim admitted update", err)
		}
		if err := b.lease.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		if err := b.lease.Release(); err != nil {
			t.Fatal(err)
		}
		if err := b.owner.Commit(ctx, b.rev, qemuNFSRebootPolicy(b.rev+1)); err != nil {
			t.Fatal(err)
		}
		if err := b.owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// The last publication is valid revision 3. Verify expects known revision 2;
	// neither it nor a repeated seed may adopt, rewrite or repair that state.
	snapshot := func() map[string][32]byte {
		t.Helper()
		out := map[string][32]byte{}
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			out[path] = sha256.Sum256(data)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	for _, phase := range []string{"seed", "verify"} {
		b := &qemuNFSReboot{}
		if err := b.policy(ctx, root, phase); err == nil {
			t.Fatal("existing or unexpected policy admitted", phase)
		}
		if !reflect.DeepEqual(before, snapshot()) {
			t.Fatal("refusal changed existing state", phase)
		}
	}
}

func TestQEMUNFSRebootRequiresOriginalAuthorities(t *testing.T) {
	for _, phase := range []string{"unknown", "seed", "verify"} {
		b := &qemuNFSReboot{}
		if err := b.run(phase); err == nil || b.seed != nil || b.owner != nil || b.lease != nil {
			t.Fatal("missing original medium/mount admitted work", phase, err)
		}
	}
}

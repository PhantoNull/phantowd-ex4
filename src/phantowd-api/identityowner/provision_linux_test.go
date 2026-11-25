// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionInitialPublishesIndependentStartupState(t *testing.T) {
	parent := identityProvisionParent(t)
	ctx := context.Background()
	if err := ProvisionInitial(ctx, parent, 23000, 23010); err != nil {
		t.Fatal(err)
	}
	if err := ProvisionInitial(ctx, parent, 24000, 24010); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing identity role could be provisioned again: %v", err)
	}
	owner, err := OpenProvisioned(parent, newModel().dependencies().inventory)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	registry, entries, err := owner.Snapshot(ctx)
	if err != nil || registry.Revision != 1 || registry.FirstID != 23000 || registry.LastID != 23010 ||
		len(registry.Accounts) != 0 || len(entries) != 0 {
		t.Fatalf("published authority lost its original range: %v", err)
	}
}

func TestProvisionInitialPreservesInterruptedStage(t *testing.T) {
	parent := identityProvisionParent(t)
	stage := filepath.Join(parent.Name(), stateStage)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stage, "interrupted")
	if err := os.WriteFile(marker, []byte("original stage"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProvisionInitial(context.Background(), parent, 23000, 23010); !errors.Is(err, ErrReview) {
		t.Fatalf("interrupted stage could be replaced: %v", err)
	}
	if owner, err := OpenProvisioned(parent, newModel().dependencies().inventory); owner != nil || !errors.Is(err, ErrReview) {
		t.Fatalf("interrupted stage admitted an identity owner: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "original stage" {
		t.Fatalf("interrupted identity evidence changed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parent.Name(), stateDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted provision published incomplete state: %v", err)
	}
}

func identityProvisionParent(t *testing.T) *os.File {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root authority test runs only in an isolated fixture")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	return parent
}

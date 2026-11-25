//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicystore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const initialInstallation = "c71c2ba76bd04d29816335c13c31a380"

func initialFixture(t *testing.T, revision uint64) (*os.File, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Close() })
	policy, err := json.MarshalIndent(emptyPolicy(revision), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return parent, append(policy, '\n')
}

func TestProvisionInitialPreservesIndependentConfirmationAcrossReopen(t *testing.T) {
	parent, base := initialFixture(t, 1)
	if err := ProvisionInitial(parent, initialInstallation, base); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent.Name(), initialPolicyName)
	for range 2 {
		owner, err := OpenConfirmedOwner(context.Background(), path, initialInstallation, base)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := owner.Snapshot(context.Background())
		if errors.Join(err, owner.Close()) != nil || policy.Revision != 1 {
			t.Fatal("cannot reopen initial policy", policy.Revision, err)
		}
	}
	if err := ProvisionInitial(parent, initialInstallation, base); !errors.Is(err, ErrConflict) {
		t.Fatal("existing state was not refused", err)
	}
	current := filepath.Join(path, "nas-services.json")
	if got, err := os.ReadFile(current); err != nil || !bytes.Equal(got, base) {
		t.Fatal("exact supplied bytes not preserved", err)
	}
	for _, tc := range []struct {
		name, id string
		base     []byte
	}{
		{"missing", initialInstallation, nil},
		{"foreign", "c71c2ba76bd04d29816335c13c31a381", base},
		{"different bytes", initialInstallation, bytes.TrimSpace(base)},
		{"pending operation", initialInstallation, base},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "pending operation" {
				if err := os.WriteFile(filepath.Join(path, ".nas-services.pending"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			owner, err := OpenConfirmedOwner(context.Background(), path, tc.id, tc.base)
			if owner != nil {
				defer owner.Close()
			}
			if err == nil {
				t.Fatal("unsafe confirmation accepted")
			}
		})
	}
	if got, err := os.ReadFile(filepath.Join(path, ".nas-services.pending")); err != nil || string(got) != "preserve" {
		t.Fatal("pending evidence changed", err)
	}
}

func TestProvisionInitialRefusesInvalidInputAndInterruptedStage(t *testing.T) {
	parent, later := initialFixture(t, 2)
	if err := ProvisionInitial(parent, initialInstallation, later); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-initial revision accepted", err)
	}
	if entries, err := os.ReadDir(parent.Name()); err != nil || len(entries) != 0 {
		t.Fatal("invalid input caused filesystem effects", err)
	}
	parent, base := initialFixture(t, 1)
	stage := filepath.Join(parent.Name(), initialStageName)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stage, "nas-evidence.json")
	if err := os.WriteFile(sentinel, []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProvisionInitial(parent, initialInstallation, base); !errors.Is(err, ErrReview) {
		t.Fatal("interrupted provisioning was not refused", err)
	}
	if _, err := os.Lstat(filepath.Join(parent.Name(), initialPolicyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted staging was published", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "interrupted" {
		t.Fatal("interrupted evidence changed", err)
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestRegisteredNFSDormantAndRefusedAdmissionReleasePolicy(t *testing.T) {
	ctx := context.Background()
	policy := nasStateTestOwner(t)
	dormant := qemuPersistentNASPolicy(2)
	dormant.FileServices.NFS.Exports = dormant.FileServices.NFS.Exports[:0]
	if err := policy.Commit(ctx, 1, dormant); err != nil {
		t.Fatal(err)
	}
	if owner, err := prepareRegisteredNFS(ctx, registeredNFSGrants{policy: policy, desired: 2}); owner != nil || err != nil {
		t.Fatal("empty NFS policy reached service preparation", err)
	}
	if err := policy.Commit(ctx, 2, qemuPersistentNASPolicy(3)); err != nil {
		t.Fatal("dormant NFS held the policy revision", err)
	}
	if owner, err := prepareRegisteredNFS(ctx, registeredNFSGrants{policy: policy, desired: 2}); owner != nil || !errors.Is(err, naspolicystore.ErrConflict) {
		t.Fatal("stale revision bypassed confirmed policy", err)
	}
	if owner, err := prepareRegisteredNFS(ctx, registeredNFSGrants{policy: policy, desired: 3}); owner != nil || !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("enabled NFS accepted missing original grants", err)
	}
	if err := policy.Commit(ctx, 3, qemuPersistentNASPolicy(4)); err != nil {
		t.Fatal("refused NFS admission retained a policy claim", err)
	}
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestStorageFromMountedOwnerSetRejectsUnprovenRoster(t *testing.T) {
	if storage, err := StorageFromMountedOwnerSet(mountowner.MountedVolumeSetEvidence{}); err != ErrNotReady ||
		storage.Complete || storage.Generation != 0 || storage.Volumes != nil {
		t.Fatalf("zero-value evidence produced a storage snapshot: snapshot=%+v err=%v", storage, err)
	}
}

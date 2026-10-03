//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// Called only inside the existing guarded VersatilePB/disposable MD fixture.
// Registry writes are test-only under fresh tmpfs scratch, never product state.
func exerciseQEMUVolumeRegistry(census trustedMountedExtCensus) error {
	dir, err := os.MkdirTemp("/run", "phantowd-registry-fixture-")
	if err != nil {
		return errors.New("registry tmpfs fixture unavailable")
	}
	defer os.RemoveAll(dir)
	var filesystem unix.Statfs_t
	if unix.Statfs(dir, &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC {
		return errors.New("registry fixture is not disposable tmpfs")
	}
	d := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: 1, Volumes: []shareconfig.Volume{{ID: "logical-registered-md", FilesystemUUID: qemuMDFilesystemUUID},
			{ID: "logical-missing", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}}}
	data, err := json.Marshal(d)
	file := filepath.Join(dir, "volumes.json")
	if err != nil || os.WriteFile(file, data, 0600) != nil {
		return errors.New("registry fixture provision failed")
	}
	f, err := os.Open(dir)
	if err != nil {
		return errors.New("registry fixture descriptor unavailable")
	}
	defer f.Close()
	r, err := volumeregistry.Open(f)
	if err != nil {
		return errors.New("protected registry reader unavailable")
	}
	defer r.Close()
	if f.Close() != nil {
		return errors.New("registry borrowed descriptor close failed")
	}
	snapshot, err := r.Read(context.Background())
	if err != nil {
		return errors.New("protected registry observation failed")
	}
	review, err := reviewRegisteredMountedVolumes(snapshot, census)
	if err != nil || review.registryRevision != 1 || review.coverage != census.coverage || len(review.volumes) != 2 ||
		review.volumes[0].volumeID != "logical-missing" || review.volumes[0].status != "not-observed-in-scope" ||
		review.volumes[0].objectCount != 0 || review.volumes[1].volumeID != "logical-registered-md" ||
		review.volumes[1].status != "observed-in-scope" || review.volumes[1].objectCount != 1 ||
		review.volumes[1].aliasCount != 1 || review.volumes[1].scopedDiskEvidenceUnresolved {
		return errors.New("registry reconciliation promoted missing or lost actual MD identity")
	}
	if _, err := json.Marshal(snapshot); err == nil {
		return errors.New("protected registry snapshot serialized")
	}
	if _, err := json.Marshal(review); err == nil {
		return errors.New("private registry review serialized")
	}
	if os.Chmod(file, 0644) != nil {
		return errors.New("registry unsafe-mode fixture failed")
	}
	if _, err := r.Read(context.Background()); !errors.Is(err, volumeregistry.ErrObservation) {
		return errors.New("unsafe registry mode accepted")
	}
	if os.Chmod(file, 0600) != nil {
		return errors.New("registry fixture mode restore failed")
	}
	if _, err := r.Read(context.Background()); err != nil {
		return errors.New("restored private fixture could not be observed")
	}
	if os.Chown(file, 12345, -1) != nil {
		return errors.New("registry foreign-owner fixture failed")
	}
	if _, err := r.Read(context.Background()); err != volumeregistry.ErrObservation {
		return errors.New("foreign registry owner accepted")
	}
	if os.Chown(file, os.Geteuid(), -1) != nil {
		return errors.New("registry fixture owner restore failed")
	}
	if _, err := r.Read(context.Background()); err != nil {
		return errors.New("restored registry fixture owner refused")
	}
	return nil
}

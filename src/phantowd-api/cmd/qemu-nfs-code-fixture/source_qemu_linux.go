//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Keep ORIGINAL parents, handles and errors after any uncertain/intentional
// fault. No fixture disposal is represented as product recovery or settlement.
var sourceRuntimeRetained any
var sourceRuntimeCause error

func probeSourceRuntime(ctx context.Context, expected []byte) (result error) {
	phase := "mount-roster"
	defer func() {
		sourceRuntimeCause = result // ORIGINAL retaining error, never only its text.
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SOURCE_FAILURE phase=%s\n", phase)
		}
	}()
	return mountowner.WithQEMUNFSSourceMountedSet(ctx, func(set *mountowner.MountedVolumeSet) error {
		lease, evidence, err := set.Acquire(ctx)
		if err != nil {
			return err
		}
		storage, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
		if err != nil || len(storage.Volumes) != 1 {
			return errors.New("source fixture lacks complete actual mounted roster")
		}
		volume := storage.Volumes[0]
		for _, name := range []string{"books", "archive"} {
			if err := os.Mkdir(filepath.Join(volume.MountPath, name), 0700); err != nil {
				return err // Exclusive fixture preparation, never in a constructor.
			}
		}
		build := func(generation uint64) (fileserviceplan.NFSv3Candidate, error) {
			registry, err := serviceaccounts.New(1000, 2000)
			if err != nil {
				return fileserviceplan.NFSv3Candidate{}, err
			}
			config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
				Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
					Volumes: []shareconfig.Volume{{ID: volume.VolumeID, FilesystemUUID: volume.FilesystemUUID}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
				NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
					Exports: []nfsconfig.Export{
						{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: volume.VolumeID, RelativePath: "books",
							Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}},
						{ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: volume.VolumeID, RelativePath: "archive",
							Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}}}
			plan, err := fileserviceplan.Build(config, 0, fileserviceplan.IdentitySnapshot{Complete: true, Generation: generation,
				Fingerprint: sha256.Sum256([]byte("synthetic-nfs-source-identity-only")), Registry: registry,
				UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}}, storage)
			if err != nil {
				return fileserviceplan.NFSv3Candidate{}, err
			}
			return plan.NFSv3TCPCandidate()
		}
		candidate, err := build(1)
		if err != nil {
			return err
		}
		phase = "original-input-pair"
		inputs, err := runtimebundle.PrepareNFSSourceInputPairQEMU(ctx, expected, candidate)
		if err != nil {
			return err
		}
		var roots *nfsowner.ExportRootsQEMU
		var joined *nfsowner.SourceRuntimeQEMU
		defer func() {
			sourceRuntimeRetained = struct {
				roster *mountowner.MountedVolumeSet
				lease  *mountowner.MountedVolumeSetLease
				roots  *nfsowner.ExportRootsQEMU
				joined *nfsowner.SourceRuntimeQEMU
				inputs [2]*runtimebundle.NFSInputsQEMU
			}{set, lease, roots, joined, inputs}
		}()
		before, err := sourceFDCount()
		if err != nil {
			return err
		}
		roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
		if err != nil {
			return err
		}
		phase = "normal-binding"
		joined, err = nfsowner.NewSourceRuntimeQEMU(ctx, roots, inputs[0])
		if err != nil {
			return err
		}
		copyJoin := *joined
		if copyJoin.Check(ctx) == nil || copyJoin.Close() == nil {
			return errors.New("copied source/runtime join accepted")
		}
		if value, err := nfsowner.NewSourceRuntimeQEMU(ctx, roots, inputs[1]); value != nil || !errors.Is(err, nfsowner.ErrBusy) {
			return errors.New("duplicate source join admitted")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if !errors.Is(joined.Check(canceled), context.Canceled) || joined.Check(ctx) != nil ||
			!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[0].Close(), processowner.ErrBusy) ||
			!errors.Is(lease.Close(), mountowner.ErrBusy) {
			return errors.New("live join failed cancellation or parent closure exclusion")
		}
		if joined.Close() != nil || joined.Close() != nil || joined.Check(ctx) == nil || roots.Check(ctx) != nil || inputs[0].Check(ctx) != nil {
			return errors.New("clean unstarted join release failed")
		}
		if roots.Close() != nil {
			return errors.New("normal source closure failed")
		}
		if after, err := sourceFDCount(); err != nil || after != before {
			return errors.New("normal source/join leaked descriptors")
		}
		phase = "same-text-different-evidence"
		changed, err := build(2)
		if err != nil {
			return err
		}
		_, a, _, _ := candidate.Documents()
		_, b, _, _ := changed.Documents()
		if a != b || candidate.EquivalentTo(changed) {
			return errors.New("changed-evidence source oracle invalid")
		}
		wrongRoots, err := nfsowner.NewExportRootsQEMU(ctx, changed, lease)
		if err != nil {
			return err
		}
		if value, err := nfsowner.NewSourceRuntimeQEMU(ctx, wrongRoots, inputs[0]); value != nil || !errors.Is(err, runtimebundle.ErrMismatch) ||
			wrongRoots.Check(ctx) != nil || wrongRoots.Close() != nil || inputs[0].Check(ctx) != nil {
			return errors.New("different source evidence admitted or original inputs poisoned")
		}
		if lease.Close() != nil || inputs[0].Close() != nil || inputs[0].Check(ctx) == nil {
			return errors.New("normal parents could not close after release")
		}
		phase = "source-fault-binding"
		lease, _, err = set.Acquire(ctx)
		if err != nil {
			return err
		}
		roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
		if err != nil {
			return err
		}
		joined, err = nfsowner.NewSourceRuntimeQEMU(ctx, roots, inputs[1])
		if err != nil || joined.Check(ctx) != nil {
			return errors.New("fault fixture failed original join")
		}
		phase = "source-replacement"
		leaf, saved := filepath.Join(volume.MountPath, "books"), filepath.Join(volume.MountPath, "books.original")
		if err := os.Rename(leaf, saved); err != nil {
			return err
		}
		if err := os.Mkdir(leaf, 0700); err != nil || !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) {
			return errors.New("source replacement admitted")
		}
		if err := os.Remove(leaf); err != nil {
			return err
		}
		if err := os.Rename(saved, leaf); err != nil {
			return err
		}
		phase = "restored-source-retained-review"
		retained, err := sourceFDCount()
		if err != nil || !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
			!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[1].Close(), processowner.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) ||
			inputs[1].Check(ctx) != nil {
			return errors.New("restoration released original source/runtime authorities")
		}
		if after, err := sourceFDCount(); err != nil || after != retained {
			return errors.New("review released original references")
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_READY original_roster=true roots=2 input_pair=true complete_candidate=true parent_closure_excluded=true copied_refused=true duplicate_refused=true canceled_unchanged=true mismatch_rollback=true normal_fd_balance=true source_replacement_review=true restored_refused=true original_refs_retained=true daemons=false kernel_backend=false product=false scope=disposable-qemu-only")
		return nil
	})
}

func sourceFDCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	return len(entries), err
}

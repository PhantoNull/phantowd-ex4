//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

// Keeps original fixture resources on any uncertain failure; no recovery API.
type nfsSourceFixtureReviewQEMU struct {
	constructionreview.Marker
	roots []*nfsowner.ExportRootsQEMU
	lease *mountowner.MountedVolumeSetLease
	cause error
}

func (*nfsSourceFixtureReviewQEMU) Error() string   { return "NFS source fixture retains review" }
func (e *nfsSourceFixtureReviewQEMU) Unwrap() error { return e.cause }

// Existing fixed mounted-volume/identity fixture only. No NFS server, kernel
// control or process starts here. All writes are exclusive fixture preparation
// on the already guarded disposable virtual data volume, never in capture.
func exerciseQEMUNFSSourceRoots(ctx context.Context, base fileservice.Config, identity *identityowner.Owner, set *mountowner.MountedVolumeSet) (result error) {
	const prefix = "nfs-source-capture"
	anchor := filepath.Join(sharePlanAnchor(), prefix)
	if err := os.Mkdir(anchor, 0700); err != nil {
		return errors.New("NFS source fixture requires fresh directory")
	}
	for _, name := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(anchor, name), 0700); err != nil {
			return err
		}
	}
	if err := os.Symlink("one", filepath.Join(anchor, "link")); err != nil {
		return err
	}
	defer func() {
		if constructionreview.Contains(result) {
			return
		}
		for _, name := range []string{"link", "one", "two", ""} {
			result = errors.Join(result, os.Remove(filepath.Join(anchor, name)))
		}
	}()
	lease, _, err := set.Acquire(ctx)
	if err != nil {
		return err
	}
	var held []*nfsowner.ExportRootsQEMU
	defer func() {
		if result != nil && (len(held) != 0 || constructionreview.Contains(result)) {
			result = &nfsSourceFixtureReviewQEMU{roots: held, lease: lease, cause: result}
			return
		}
		closeErr := lease.Close()
		result = errors.Join(result, closeErr)
		if closeErr != nil {
			result = &nfsSourceFixtureReviewQEMU{roots: held, lease: lease, cause: result}
		}
	}()
	config := base
	config.NFS.Exports = slices.Clone(base.NFS.Exports)
	config.NFS.Exports[0].RelativePath = prefix + "/one"
	other := config.NFS.Exports[0]
	other.ID, other.RelativePath = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", prefix+"/two"
	other.Clients = slices.Clone(other.Clients)
	other.Clients[0].Access = "rw"
	config.NFS.Exports = append(config.NFS.Exports, other)
	build := func(c fileservice.Config) (fileserviceplan.NFSv3Candidate, error) {
		plan, err := fileserviceplan.BuildFromOwners(ctx, c, 0, identity, set)
		if err != nil {
			return fileserviceplan.NFSv3Candidate{}, err
		}
		return plan.NFSv3TCPCandidate()
	}
	candidate, err := build(config)
	if err != nil {
		return err
	}
	roots, err := nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
	if err != nil {
		return err
	}
	held = append(held, roots)
	if err := roots.Check(ctx); err != nil {
		return err
	}
	copyRoots := *roots
	if copyRoots.Check(ctx) != nfsowner.ErrInvalid || copyRoots.Close() != nfsowner.ErrInvalid {
		return errors.New("NFS copied source lifetime accepted")
	}
	if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
		return errors.New("NFS live source pins did not retain the original roster lease")
	}
	if err := roots.Close(); err != nil {
		return err
	}
	if err := roots.Close(); err != nil {
		return err
	}
	if roots.Check(ctx) == nil {
		return errors.New("NFS closed source lifetime revived")
	}
	// Whole-volume NFS is distinct from SMB's prohibited whole-volume share.
	whole := config
	whole.NFS.Exports = slices.Clone(config.NFS.Exports[:1])
	whole.NFS.Exports[0].RelativePath = "."
	wholeCandidate, err := build(whole)
	if err != nil {
		return err
	}
	wholeRoots, err := nfsowner.NewExportRootsQEMU(ctx, wholeCandidate, lease)
	if err != nil {
		return err
	}
	held = append(held, wholeRoots)
	if err := wholeRoots.Check(ctx); err != nil {
		return err
	}
	if err := wholeRoots.Close(); err != nil {
		return err
	}
	for _, leaf := range []string{"missing", "link"} {
		bad := whole
		bad.NFS.Exports = slices.Clone(whole.NFS.Exports)
		bad.NFS.Exports[0].RelativePath = prefix + "/" + leaf
		badCandidate, err := build(bad)
		if err != nil {
			return err
		}
		captured, captureErr := nfsowner.NewExportRootsQEMU(ctx, badCandidate, lease)
		if captured != nil {
			held = append(held, captured)
		}
		if captureErr == nil || captured != nil || constructionreview.Contains(captureErr) {
			return errors.Join(errors.New("NFS absent/symlink source did not roll back cleanly"), captureErr)
		}
	}
	// Hold original objects while replacing one selected path; no service exists.
	roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
	if err != nil {
		return err
	}
	held = append(held, roots)
	one, saved := filepath.Join(anchor, "one"), filepath.Join(anchor, "saved")
	if err := os.Rename(one, saved); err != nil {
		return err
	}
	if err := os.Mkdir(one, 0700); err != nil {
		return err
	}
	if !errors.Is(roots.Check(ctx), nfsowner.ErrReviewRequired) {
		return errors.New("NFS replacement directory retained source authority")
	}
	if err := os.Remove(one); err != nil {
		return err
	}
	if err := os.Rename(saved, one); err != nil {
		return err
	}
	if !errors.Is(roots.Check(ctx), nfsowner.ErrReviewRequired) {
		return errors.New("NFS restored source erased lifetime review")
	}
	if !errors.Is(roots.Close(), nfsowner.ErrReviewRequired) {
		return errors.New("NFS explicit source disposal erased review")
	}
	// No consumers have ever started. Group Close proves all source pins released;
	// it does not recover a reviewed service or an uncertain descriptor close.
	if err := lease.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_ROOTS_READY roots=2 roster=original_lease mixed_roles=true whole_volume=true absent_refused=true symlink_refused=true replacement_review=true restored_refused=true parent_close_blocked=true capture_writes=false kernel_backend=false service=false scope=disposable-qemu-only")
	return nil
}

func sharePlanAnchor() string { return "/srv/phantowd/volumes/" + string(qemuPlannerVolumeID) }

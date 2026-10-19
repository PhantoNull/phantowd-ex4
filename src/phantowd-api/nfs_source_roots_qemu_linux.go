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
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

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
		for _, name := range []string{"link", "one", "two", ""} {
			result = errors.Join(result, os.Remove(filepath.Join(anchor, name)))
		}
	}()
	lease, _, err := set.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
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
		if captured, err := nfsowner.NewExportRootsQEMU(ctx, badCandidate, lease); err == nil || captured != nil || constructionreview.Contains(err) {
			return errors.New("NFS absent/symlink source did not roll back cleanly")
		}
	}
	// Hold original objects while replacing one selected path; no service exists.
	roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
	if err != nil {
		return err
	}
	// Real source references, synthetic consumer only. The original lifecycle
	// must detect loss itself and retain these pins after verified model stop.
	backend := &qemuNFSSourceConsumer{roots: roots, config: config, identity: identity, roster: set}
	supervised, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		return err
	}
	if err := supervised.Start(ctx); err != nil {
		return err
	}
	one, saved := filepath.Join(anchor, "one"), filepath.Join(anchor, "saved")
	if err := os.Rename(one, saved); err != nil {
		return err
	}
	if err := os.Mkdir(one, 0700); err != nil {
		return err
	}
	if !errors.Is(supervised.Supervise(ctx, time.Second), nfsowner.ErrReviewRequired) || backend.running || backend.stops != 1 || backend.releases != 0 {
		return errors.New("NFS supervised source loss did not retain stopped original authority")
	}
	if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
		return errors.New("NFS reviewed supervised source pins were released")
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
	if !errors.Is(supervised.Supervise(ctx, time.Second), nfsowner.ErrReviewRequired) ||
		!errors.Is(supervised.Close(ctx), nfsowner.ErrReviewRequired) || backend.stops != 1 || backend.releases != 0 {
		return errors.New("NFS restored supervised source revived or released authority")
	}
	// Explicit no-consumer fixture disposal only, not reviewed-Owner recovery.
	if !errors.Is(roots.Close(), nfsowner.ErrReviewRequired) {
		return errors.New("NFS explicit source disposal erased review")
	}
	// No consumers have ever started. Group Close proves all source pins released;
	// it does not recover a reviewed service or an uncertain descriptor close.
	if err := lease.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_ROOTS_READY roots=2 roster=original_lease mixed_roles=true whole_volume=true absent_refused=true symlink_refused=true replacement_review=true restored_refused=true parent_close_blocked=true capture_writes=false service=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NFS_SUPERVISION_READY exclusive_owner=true source=original_roster roots=retained automatic_loss_detection=true model_stop_once=true review_pins_retained=true restored_refused=true policy=synthetic kernel_backend=false restart=false scope=disposable-qemu-only")
	return nil
}

func sharePlanAnchor() string { return "/srv/phantowd/volumes/" + string(qemuPlannerVolumeID) }

// Fixture backend only: fresh identity/storage planning and real root checks,
// but no retained policy owner, code, daemon, kernel or data-access authority.
type qemuNFSSourceConsumer struct {
	roots           *nfsowner.ExportRootsQEMU
	config          fileservice.Config
	identity        *identityowner.Owner
	roster          *mountowner.MountedVolumeSet
	running         bool
	stops, releases int
}

func (b *qemuNFSSourceConsumer) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	plan, err := fileserviceplan.BuildFromOwners(ctx, b.config, 0, b.identity, b.roster)
	if err != nil || !candidate.FreshAgainst(plan.Freshness()) {
		return nfsowner.ErrReviewRequired
	}
	return b.roots.Check(ctx)
}
func (b *qemuNFSSourceConsumer) VerifyStopped(context.Context) error {
	if b.running {
		return nfsowner.ErrReviewRequired
	}
	return nil
}
func (b *qemuNFSSourceConsumer) Start(context.Context) error { b.running = true; return nil }
func (b *qemuNFSSourceConsumer) VerifyReady(context.Context) error {
	if !b.running {
		return nfsowner.ErrReviewRequired
	}
	return nil
}
func (b *qemuNFSSourceConsumer) Stop(ctx context.Context) error {
	if ctx.Err() != nil {
		return nfsowner.ErrReviewRequired
	}
	b.stops++
	b.running = false
	return nil
}
func (b *qemuNFSSourceConsumer) Release(context.Context) error {
	b.releases++
	if b.running {
		return nfsowner.ErrReviewRequired
	}
	return b.roots.Close()
}

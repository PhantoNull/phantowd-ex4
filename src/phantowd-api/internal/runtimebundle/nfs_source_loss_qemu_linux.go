//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

var errNFSSourceLossQEMU = errors.New("fixed NFS source-loss fixture retains live consumers")

type nfsSourceLossEvidenceQEMU struct {
	kernel                                  *nfskernel.ControllerQEMU
	companions                              [2]nfsCompanionQEMU
	held                                    unix.Stat_t
	verified                                bool
	withdrawalAttempted, withdrawalVerified bool
	withdrawalCause                         error
}

func nfsSourceLossExpectedQEMU(s *nfsCodeLifetimeQEMU, err error) bool {
	return s != nil && s.sourceAccess != nil && s.sourceAccess.sourceLoss && s.sourceAccess.lossTriggered &&
		s.sourceAccess.loss != nil && s.sourceAccess.loss.verified && errors.Is(err, errNFSSourceLossQEMU)
}

// Explicit mutation of the already guarded disposable volume only. This is
// fault injection, never product startup, policy replay or data migration.
func (o *NFSSourceAccessQEMU) exerciseSourceLossQEMU(ctx context.Context) error {
	if !o.sourceLoss || o.lossTriggered || o.capture != nil || len(o.mounts) != 2 || !o.exportsLoaded {
		return ErrInvalid
	}
	var err error
	o.heldClient, err = os.Open(nfsSourceClientsQEMU + "/books/created")
	if err != nil {
		return err
	}
	volume := int(o.volume.Fd())
	if err := unix.Fstat(int(o.heldClient.Fd()), &o.heldClientIdentity); err != nil {
		return err
	}
	for _, name := range []string{"books.original", "books.replacement"} {
		var st unix.Stat_t
		if err := unix.Fstatat(volume, name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return ErrMismatch
		}
	}
	if err := unix.Renameat(volume, "books", volume, "books.original"); err != nil {
		return err
	}
	if err := unix.Mkdirat(volume, "books", 0700); err != nil {
		return err
	}
	if err := unix.Fchownat(volume, "books", 1000, 1000, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	fd, err := unix.Openat2(volume, "books/created", &unix.OpenHow{Flags: unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	o.faultFile = os.NewFile(uintptr(fd), "fixed-nfs-loss-byte-identical-replacement")
	n, writeErr := o.faultFile.WriteString(nfsSourcePayloadQEMU)
	if writeErr != nil || n != len(nfsSourcePayloadQEMU) {
		return errors.Join(ErrMismatch, writeErr)
	}
	if err := unix.Fchown(fd, 1000, 1000); err != nil {
		return err
	}
	if err := o.faultFile.Sync(); err != nil {
		return err
	}
	data := make([]byte, len(nfsSourcePayloadQEMU))
	if _, err := o.faultFile.ReadAt(data, 0); err != nil || string(data) != nfsSourcePayloadQEMU {
		return errors.Join(ErrMismatch, err)
	}
	if err := o.faultFile.Close(); err != nil {
		return err
	}
	o.faultFile = nil
	if err := o.check(ctx); err == nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_LOSS_FAILURE phase=replacement-accepted")
		return errors.New("byte-identical source replacement accepted during live NFS access")
	}
	if !o.review || !errors.Is(o.cause, ErrMismatch) {
		return ErrMismatch
	}
	if err := unix.Renameat(volume, "books", volume, "books.replacement"); err != nil {
		return err
	}
	if err := unix.Renameat(volume, "books.original", volume, "books"); err != nil {
		return err
	}
	if !errors.Is(o.check(ctx), ErrReviewRequired) || o.checkReferences(ctx) != nil || o.checkSourceBindings(ctx) != nil {
		return ErrMismatch
	}
	// ONE ordinary attempt. Never retry, force or detach an active client mount.
	if err := unix.Unmount(nfsSourceClientsQEMU+"/books", 0); !errors.Is(err, unix.EBUSY) {
		return errors.Join(ErrMismatch, err)
	}
	o.lossTriggered = true
	return errors.Join(ErrReviewRequired, errNFSSourceLossQEMU, o.cause)
}

func (o *NFSSourceAccessQEMU) observeSourceLossConsumersQEMU(ctx context.Context) error {
	if o.loss == nil || o.loss.kernel == nil || !o.lossTriggered || !o.review || o.heldClient == nil || o.faultFile != nil || o.settled || o.closed || len(o.mounts) != 2 || !o.exportsLoaded {
		return ErrMismatch
	}
	if o.loss.kernel.CheckRunning(ctx) != nil || o.checkReferences(ctx) != nil {
		return ErrMismatch
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(o.heldClient.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 1000 || st.Gid != 1000 || st.Nlink != 1 ||
		unix.Fstatfs(int(o.heldClient.Fd()), &fs) != nil || fs.Type != unix.NFS_SUPER_MAGIC {
		return ErrMismatch
	}
	if o.loss.held.Ino == 0 || st.Dev != o.loss.held.Dev || st.Ino != o.loss.held.Ino || st.Mode != o.loss.held.Mode || st.Uid != o.loss.held.Uid || st.Gid != o.loss.held.Gid {
		return ErrMismatch
	}
	for index, companion := range o.loss.companions {
		if companion.owner == nil || companion.pid <= 0 {
			return ErrMismatch
		}
		state, err := companion.owner.Observe(ctx)
		if err != nil || state.State != processowner.StateReady || state.Generation != 1 || len(state.Members) != 1 || state.Members[0].Process.PID != companion.pid || state.Members[0].Process.DiagnosticsTruncated {
			return errors.Join(ErrMismatch, err)
		}
		if ok, err := nfsRPCNullQEMU(ctx, index == 1); err != nil || !ok {
			return errors.Join(ErrMismatch, err)
		}
	}
	if o.loss.companions[0].owner.CheckNFSRPCBindHandoffQEMU(ctx) != nil || o.loss.companions[1].owner.CheckNFSSourceMountdAccessHandoffQEMU(ctx, false) != nil {
		return ErrMismatch
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || !ok {
		return errors.Join(ErrMismatch, err)
	}
	return nil
}

// Read-only verification of this ORIGINAL reviewed fault lifetime. It grants
// neither retry/restart nor closure, and never returns raw handles or records.
func (o *NFSSourceAccessQEMU) VerifySourceLossRetainedQEMU(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.sourceLoss || !o.consumed || !o.review || o.cause == nil || o.loss == nil || !o.loss.verified {
		return ErrInvalid
	}
	if err := o.lease.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.lease.gate }()
	s, err := o.lease.parent.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	if !s.review || !s.sourceReserved || s.sourceAccess != o || o.lease.consumer != o || o.lease.closed || s.closed {
		return ErrMismatch
	}
	if !errors.Is(o.check(ctx), ErrReviewRequired) || o.checkSourceBindings(ctx) != nil {
		return ErrMismatch
	}
	return o.observeSourceLossConsumersQEMU(ctx)
}

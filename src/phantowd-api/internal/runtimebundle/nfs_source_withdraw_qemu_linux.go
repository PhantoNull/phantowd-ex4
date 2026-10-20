//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const nfsSourceWithdrawHandoffQEMU = "PHANTOWD_NFS_WITHDRAW_HANDOFF private_view=true capabilities_zero=true data_roots=false flush=4 fixed_exportfs=true\n"

// One fixed fault-fixture operation, not product cleanup/recovery authority.
// The fixture cancels its admitted request before mutation; cleanup then owns a
// separate fixed five-second budget. Review and all parent lifetimes survive.
func (o *NFSSourceAccessQEMU) WithdrawSourceLossFixtureQEMU(ctx context.Context) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.sourceLoss || !nfsSourceAccessSelectorQEMU(true) || !o.consumed || !o.review || o.cause == nil || o.loss == nil || !o.loss.verified {
		return ErrInvalid
	}
	if o.loss.withdrawalAttempted {
		return ErrReviewRequired
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
	if !s.review || !s.sourceReserved || s.sourceAccess != o || o.lease.consumer != o || o.lease.closed || s.closed || o.capture != nil {
		return ErrReviewRequired
	}
	request, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	if s.revalidateReferences(request) != nil || o.observeSourceLossConsumersQEMU(request) != nil {
		return ErrReviewRequired
	}
	before, err := o.cachedClientReferencesQEMU()
	if err != nil {
		return err
	}
	if err := request.Err(); err != nil {
		return err
	}
	o.loss.withdrawalAttempted = true // No retry even after uncertain effects.
	cancelRequest()                   // Deterministic post-admission cancellation in this fixture.
	if !errors.Is(request.Err(), context.Canceled) {
		return ErrReviewRequired
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	phase := "withdraw"
	defer func() {
		if result != nil {
			o.loss.withdrawalCause = result // Keep the original failure object.
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_WITHDRAW_FAILURE phase=%s\n", phase)
		}
	}()
	for _, role := range []processowner.NFSWithdrawalOperationQEMU{processowner.NFSWithdrawOwnedQEMU, processowner.NFSFlushOwnedQEMU} {
		if err := o.withdrawExportQEMU(cleanup, s, role); err != nil {
			return err
		}
	}
	fd, err := unix.Openat2(int(s.state.root.Fd()), "nfs/etab", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	o.faultFile = os.NewFile(uintptr(fd), "original-state-withdrawn-table")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Size != 0 {
		return ErrMismatch
	}
	if err := o.faultFile.Close(); err != nil {
		return err
	}
	o.faultFile = nil
	o.exportsLoaded = false
	phase = "kernel-stop"
	if err := o.loss.kernel.Stop(cleanup); err != nil {
		return err
	}
	if err := o.loss.kernel.CheckStopped(cleanup); err != nil {
		return err
	}
	if ok, err := nfsFixedNullQEMU(cleanup, "127.0.0.1:2049", 100003, 3); err != nil || ok {
		return errors.Join(ErrMismatch, err)
	}
	phase = "daemon-stop"
	// Stop original mountd before original rpcbind. Keep both input Owners/pins.
	for _, index := range []int{1, 0} {
		companion := o.loss.companions[index]
		stopped, err := companion.owner.Stop(cleanup)
		if err != nil || stopped.State != processowner.StateStopped || stopped.Generation != 1 || len(stopped.Members) != 1 ||
			stopped.Members[0].Process.PID != 0 || stopped.Members[0].Process.DiagnosticsTruncated || !errors.Is(unix.Kill(-companion.pid, 0), unix.ESRCH) {
			return errors.Join(ErrReviewRequired, err)
		}
		if inode, err := nfsRPCListenerQEMU(index == 1); err != nil || inode != "" {
			return errors.Join(ErrMismatch, err)
		}
	}
	phase = "stopped-original-references"
	if o.loss.companions[1].owner.CheckNFSSourceMountdAccessHandoffQEMU(cleanup, true) != nil ||
		o.loss.companions[0].owner.CheckNFSRPCBindHandoffQEMU(cleanup) != nil || o.loss.kernel.CheckStopped(cleanup) != nil ||
		s.revalidateReferences(cleanup) != nil || o.checkReferences(cleanup) != nil {
		return ErrMismatch
	}
	after, err := o.cachedClientReferencesQEMU()
	if err != nil || before != after || o.closed || o.settled || !o.review || o.cause == nil || o.exportsLoaded || o.capture != nil ||
		!s.review || !s.sourceReserved || s.sourceAccess != o || o.lease.consumer != o {
		return errors.Join(ErrReviewRequired, err)
	}
	if err := cleanup.Err(); err != nil {
		return err
	}
	o.loss.withdrawalVerified = true
	return nil
}

func (o *NFSSourceAccessQEMU) withdrawExportQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, role processowner.NFSWithdrawalOperationQEMU) error {
	if o.capture != nil || s.revalidateReferences(ctx) != nil || o.checkReferences(ctx) != nil {
		return ErrMismatch
	}
	program := s.code.files["usr/sbin/exportfs"]
	for _, alias := range s.code.plan.aliases {
		if alias.Path == "usr/sbin/exportfs" {
			program = s.code.files[alias.Target]
		}
	}
	if program == nil {
		return ErrMismatch
	}
	extra := [6]*os.File{o.features, o.channels.flush[0], o.channels.flush[1], o.channels.flush[2], o.channels.flush[3], o.channels.namespaces[0]}
	var err error
	o.capture, err = processowner.NewNFSWithdrawalCaptureQEMU(role, o.bootstrap, o.input, [4]*os.File{s.code.root, s.configuration.contents.root, s.state.root, program}, extra)
	if err != nil {
		return err
	}
	result, err := o.capture.Capture(ctx)
	if err != nil {
		return err
	}
	if result.Kind != processowner.CaptureExited || result.ExitCode != 0 || len(result.Stdout) != 0 || string(result.Stderr) != nfsSourceWithdrawHandoffQEMU {
		fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_WITHDRAW_EXPORT_FAILURE role=%s kind=%d exit=%d stderr=%q\n", role, result.Kind, result.ExitCode, result.Stderr)
		return ErrMismatch
	}
	return o.closeCapture(ctx)
}

type nfsCachedClientReferenceQEMU struct {
	inode, mount uint64
	major, minor uint32
	typeBits     uint16
}

// No Fstat/Fstatfs, read or remote lookup after server stop. Linux 6.18 NFS
// getattr honors DONT_SYNC without FORCE_SYNC; root/held-file metadata below
// are cached identity observations, NOT proof of I/O or client quiescence.
func (o *NFSSourceAccessQEMU) cachedClientReferencesQEMU() (result [3]nfsCachedClientReferenceQEMU, err error) {
	if len(o.mounts) != 2 || o.heldClient == nil {
		return result, ErrMismatch
	}
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	for index := range result {
		fd, path, flags := unix.AT_FDCWD, "", unix.AT_STATX_DONT_SYNC|unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW
		kind := uint16(unix.S_IFDIR)
		if index < 2 {
			path = o.mounts[index].path
		} else {
			fd, flags, kind = int(o.heldClient.Fd()), flags|unix.AT_EMPTY_PATH, unix.S_IFREG
			if _, err := unix.FcntlInt(o.heldClient.Fd(), unix.F_GETFL, 0); err != nil {
				return result, err
			}
		}
		var st unix.Statx_t
		if unix.Statx(fd, path, flags, mask, &st) != nil || st.Mask&mask != mask || st.Mode&unix.S_IFMT != kind || st.Ino == 0 || st.Mnt_id == 0 {
			return result, ErrMismatch
		}
		if index == 2 && (st.Ino != o.loss.held.Ino || st.Dev_major != unix.Major(uint64(o.loss.held.Dev)) || st.Dev_minor != unix.Minor(uint64(o.loss.held.Dev))) {
			return result, ErrMismatch
		}
		result[index] = nfsCachedClientReferenceQEMU{st.Ino, st.Mnt_id, st.Dev_major, st.Dev_minor, st.Mode & unix.S_IFMT}
	}
	return result, nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"golang.org/x/sys/unix"
)

// Fixed disposable source server. Original instances survive across calls;
// gates cover ONE operation, never the intervals between operations. These
// refs do not certify sole NFSD authority, client quiescence or recovery.
type nfsServerQEMU struct {
	source                                       *NFSSourceAccessQEMU
	code                                         *nfsCodeLifetimeQEMU
	rpcbind, mountd                              *nfsDaemonQEMU
	kernel                                       *nfskernel.ControllerQEMU
	beforeRPC, beforeMountd, beforeKernel        int
	table                                        nfsServerTableQEMU
	running, ioAttempted, stopAttempted, stopped bool
	phase                                        string
}

type nfsServerTableQEMU struct {
	stamp  unix.Stat_t
	digest [32]byte
}

func (o *NFSSourceAccessQEMU) StartServerFixtureQEMU(ctx context.Context) error {
	return o.serverOperation(ctx, 0)
}
func (o *NFSSourceAccessQEMU) CheckServerFixtureQEMU(ctx context.Context) error {
	return o.serverOperation(ctx, 1)
}
func (o *NFSSourceAccessQEMU) ExerciseServerIOFixtureQEMU(ctx context.Context) error {
	return o.serverOperation(ctx, 2)
}
func (o *NFSSourceAccessQEMU) StopServerFixtureQEMU(ctx context.Context) error {
	return o.serverOperation(ctx, 3)
}

func (o *NFSSourceAccessQEMU) CheckServerStoppedFixtureQEMU(ctx context.Context) error {
	return o.serverOperation(ctx, 4)
}

func (o *NFSSourceAccessQEMU) serverOperation(ctx context.Context, operation uint8) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.closed {
		return ErrUnavailable
	}
	if o.review {
		return ErrReviewRequired
	}
	if o.sourceLoss || o.daemonLoss || operation > 4 {
		return ErrInvalid
	}
	if operation == 0 {
		if o.consumed || o.server != nil {
			return ErrUnavailable
		}
	} else if operation == 4 {
		if o.consumed || o.server != nil {
			if !o.consumed || o.server == nil || !o.settled || !o.server.stopped {
				return ErrUnavailable
			}
		}
	} else if !o.consumed || o.server == nil || o.settled || operation == 2 && o.server.ioAttempted || operation == 3 && o.server.stopAttempted {
		return ErrUnavailable
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
	defer func() {
		if result != nil {
			o.review = true
			if o.cause == nil {
				o.cause = result
			}
			if !s.review {
				s.review, s.cause = true, result
			}
			phase := "admission"
			if o.server != nil {
				phase = o.server.phase
			}
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SERVER_FAILURE phase=%s\n", phase)
		}
	}()
	beforeStart := operation == 0 || operation == 4 && !o.consumed
	if o.lease.consumer != o || beforeStart && s.sourceAccess != nil || !beforeStart && s.sourceAccess != o || o.lease.revalidate(ctx, s) != nil || o.check(ctx) != nil {
		return ErrReviewRequired
	}
	if operation == 4 {
		return o.observeServerStopped(ctx, s)
	}
	if operation == 0 {
		o.consumed, s.sourceAccess = true, o
		o.server = &nfsServerQEMU{source: o, code: s, phase: "prepare"}
		return o.server.start(ctx)
	}
	if o.server.source != o || o.server.code != s {
		return ErrMismatch
	}
	switch operation {
	case 1:
		return o.server.check(ctx)
	case 2:
		o.server.ioAttempted = true
		if err := o.server.check(ctx); err != nil {
			return err
		}
		if err := o.exerciseIO(ctx, s); err != nil {
			return err
		}
		return o.server.check(ctx)
	case 3:
		o.server.stopAttempted = true
		// One admitted cleanup receives its own combined five-second budget.
		// Pre-admission cancellation has already refused without effects.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := o.server.stop(cleanup); err != nil {
			return err
		}
		o.settled = true
		return nil
	}
	return ErrInvalid
}

// A fresh stopped sample under ORIGINAL control, namespace, code and state
// references. This is a fixed fixture profile, NOT sole-domain ownership,
// complete export-cache census, remote-client quiescence or release authority.
// Every legacy read gets a new transaction descriptor (no seek/stale snapshot).
func (o *NFSSourceAccessQEMU) observeServerStopped(ctx context.Context, s *nfsCodeLifetimeQEMU) error {
	if o.exportsLoaded || o.capture != nil || len(o.mounts) != 0 || o.heldClient != nil || o.faultFile != nil {
		return ErrUnavailable
	}
	for _, mountd := range []bool{false, true} {
		if inode, err := nfsRPCListenerQEMU(mountd); err != nil || inode != "" {
			return errors.Join(ErrMismatch, err)
		}
	}
	var profile [3][]byte
	for index, name := range []string{"threads", "versions", "portlist"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := openBeneath(int(o.controlRoot.Fd()), name, unix.O_RDONLY)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), "original-nfs-stopped-transaction")
		o.faultFile = f
		var st unix.Statx_t
		const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_UID | unix.STATX_GID | unix.STATX_MNT_ID_UNIQUE
		if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &st) != nil || st.Mask&mask != mask ||
			st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 || st.Uid != 0 || st.Gid != 0 || st.Mnt_id != o.controlMetadata[0].Mnt_id {
			err = ErrMismatch
		} else {
			profile[index], err = io.ReadAll(io.LimitReader(f, 4097))
			if len(profile[index]) > 4096 {
				err = ErrMismatch
			}
		}
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(ErrReviewRequired, err, closeErr) // Original object retained, never retry Close.
		}
		o.faultFile = nil
		if err != nil {
			return err
		}
	}
	if err := nfskernel.ValidateProfileQEMU(profile[0], profile[1], profile[2], false); err != nil {
		return err
	}
	var named unix.Stat_t
	err := unix.Fstatat(int(s.state.root.Fd()), "nfs/etab", &named, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) || o.consumed {
			return err
		}
	} else {
		view := nfsServerQEMU{source: o, code: s}
		if _, count, err := view.observeTable(ctx); err != nil || count != 0 {
			return errors.Join(ErrMismatch, err)
		}
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || ok {
		return errors.Join(ErrMismatch, err)
	}
	if err := o.check(ctx); err != nil {
		return err
	}
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (v *nfsServerQEMU) start(ctx context.Context) error {
	o, s := v.source, v.code
	for _, mountd := range []bool{false, true} {
		if inode, err := nfsRPCListenerQEMU(mountd); err != nil || inode != "" {
			return errors.Join(ErrMismatch, err)
		}
	}
	var err error
	v.beforeRPC, err = retainedFixtureFDCount()
	if err != nil {
		return err
	}
	v.phase = "rpcbind-construct"
	v.rpcbind, err = newNFSDaemonQEMU(ctx, s, o.bootstrap, nil, false)
	if err != nil {
		return err
	}
	v.phase = "rpcbind-start"
	if err := v.rpcbind.start(ctx); err != nil {
		return err
	}
	v.phase = "rpcbind-ready"
	if err := v.rpcbind.check(ctx); err != nil {
		return err
	}
	v.beforeMountd, err = retainedFixtureFDCount()
	if err != nil {
		return err
	}
	v.phase = "mountd-construct"
	v.mountd, err = newNFSDaemonQEMU(ctx, s, o.bootstrap, o.channels, true)
	if err != nil {
		return err
	}
	v.phase = "mountd-start"
	if err := v.mountd.start(ctx); err != nil {
		return err
	}
	v.phase = "mountd-ready"
	if err := v.mountd.check(ctx); err != nil {
		return err
	}
	v.beforeKernel, err = retainedFixtureFDCount()
	if err != nil {
		return err
	}
	v.phase = "kernel-construct"
	v.kernel, err = nfskernel.OpenCodeQEMU(ctx)
	if err != nil {
		return err
	}
	v.phase = "kernel-start"
	if err := v.kernel.Start(ctx); err != nil {
		return err
	}
	v.phase = "activate-exports"
	if err := o.activateExports(ctx, s); err != nil {
		return err
	}
	v.phase = "capture-export-table"
	v.table, _, err = v.observeTable(ctx)
	if err != nil {
		return err
	}
	v.running = true
	return v.check(ctx)
}

func (v *nfsServerQEMU) check(ctx context.Context) error {
	if !v.running || v.stopped || !v.source.exportsLoaded {
		return ErrUnavailable
	}
	v.phase = "original-daemons"
	if err := v.rpcbind.check(ctx); err != nil {
		return err
	}
	if err := v.mountd.check(ctx); err != nil {
		return err
	}
	v.phase = "original-kernel"
	if err := v.kernel.CheckRunning(ctx); err != nil {
		return err
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || !ok {
		return errors.Join(ErrMismatch, err)
	}
	v.phase = "original-export-table"
	now, count, err := v.observeTable(ctx)
	if err != nil || count == 0 || !sameNFSServerTableQEMU(now, v.table) {
		return errors.Join(ErrMismatch, err)
	}
	if err := v.code.revalidate(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (v *nfsServerQEMU) stop(ctx context.Context) error {
	if !v.running || v.stopped || len(v.source.mounts) != 0 || v.source.capture != nil {
		return ErrUnavailable
	}
	if err := v.check(ctx); err != nil {
		return err
	}
	v.phase = "withdraw-exports"
	if err := v.source.withdrawExports(ctx, v.code); err != nil {
		return err
	}
	if v.source.accessComplete {
		emitNFSSourceIOReadyQEMU()
	}
	v.phase = "kernel-stop"
	if err := v.kernel.Stop(ctx); err != nil {
		return err
	}
	if err := v.kernel.CheckStopped(ctx); err != nil {
		return err
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || ok {
		return errors.Join(ErrMismatch, err)
	}
	if err := v.rpcbind.check(ctx); err != nil {
		return err
	}
	if err := v.mountd.check(ctx); err != nil {
		return err
	}
	if err := v.kernel.Close(ctx); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != v.beforeKernel {
		return errors.Join(ErrMismatch, err)
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_KERNEL_READY original_control=true original_namespaces=true original_daemons_live=true threads=2 stop_verified=true fd_balance=true exports_withdrawn=true owner_backend=false product=false scope=qemu-only")
	v.phase = "mountd-stop"
	if err := v.mountd.stop(ctx); err != nil {
		return err
	}
	if err := v.mountd.checkStopped(ctx); err != nil {
		return err
	}
	if err := v.mountd.close(); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != v.beforeMountd {
		return errors.Join(ErrMismatch, err)
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_MOUNTD_READY original_channels=3 original_sources=3 filehandle_view=true private_view=true uid_gid=0 caps=dac-read-search listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only")
	v.phase = "rpcbind-stop"
	if err := v.rpcbind.stop(ctx); err != nil {
		return err
	}
	if err := v.rpcbind.checkStopped(ctx); err != nil {
		return err
	}
	if err := v.rpcbind.close(); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != v.beforeRPC {
		return errors.Join(ErrMismatch, err)
	}
	v.phase = "owned-state-cleanup"
	if err := v.code.revalidate(ctx); err != nil {
		return err
	}
	if err := cleanNFSRPCBindStateQEMU(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_RPCBIND_READY original_inputs=true uid_gid=1 capabilities_zero=true listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only")
	v.running, v.stopped = false, true
	return ctx.Err()
}

func sameNFSServerTableQEMU(a, b nfsServerTableQEMU) bool {
	x, y := a.stamp, b.stamp
	return a.digest == b.digest && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

// Already-retained private nodev TMPFS role: nonblocking/BENEATH opening and
// regular-file checks precede the bounded read. No disk path is read. Preserve
// an uncertain Close object instead of retrying that descriptor number.
func (v *nfsServerQEMU) observeTable(ctx context.Context) (nfsServerTableQEMU, int, error) {
	var zero nfsServerTableQEMU
	if err := ctx.Err(); err != nil {
		return zero, 0, err
	}
	if v.source.faultFile != nil {
		return zero, 0, ErrReviewRequired
	}
	fd, err := openBeneath(int(v.code.state.root.Fd()), "nfs/etab", unix.O_RDONLY|unix.O_NOATIME)
	if err != nil {
		return zero, 0, err
	}
	f := os.NewFile(uintptr(fd), "original-nfs-server-export-table")
	v.source.faultFile = f
	var before, after, named unix.Stat_t
	valid := unix.Fstat(fd, &before) == nil && before.Mode == unix.S_IFREG|0600 && before.Uid == 0 && before.Gid == 0 && before.Nlink == 1 && before.Size >= 0 && before.Size <= 16<<10
	var data []byte
	if valid {
		data, err = io.ReadAll(io.LimitReader(f, (16<<10)+1))
	} else {
		err = ErrMismatch
	}
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(int(v.code.state.root.Fd()), "nfs/etab", &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		err = errors.Join(err, ErrMismatch)
	}
	if closeErr := f.Close(); closeErr != nil {
		return zero, 0, errors.Join(ErrReviewRequired, err, closeErr)
	}
	v.source.faultFile = nil
	stamp := nfsServerTableQEMU{stamp: before, digest: sha256.Sum256(data)}
	if err != nil || len(data) > 16<<10 || int64(len(data)) != before.Size || !sameNFSServerTableQEMU(stamp, nfsServerTableQEMU{stamp: after, digest: stamp.digest}) || !sameNFSServerTableQEMU(stamp, nfsServerTableQEMU{stamp: named, digest: stamp.digest}) {
		return zero, 0, errors.Join(ErrMismatch, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, 0, err
	}
	return stamp, len(data), nil
}

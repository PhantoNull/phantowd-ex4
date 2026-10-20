//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

var nfsMountdUnsettledQEMU bool
var nfsMountdRetainedQEMU any

// Positive metadata observation only: no read/dequeue from a kernel channel.
func observeNFSMountdChannelsQEMU(pid int, channels *NFSMountdChannelsQEMU) error {
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	root := fmt.Sprintf("/proc/%d", pid)
	fds, err := os.ReadDir(root + "/fd")
	if err != nil || len(fds) > 128 {
		return errors.Join(ErrMismatch, err)
	}
	for index, name := range nfsMountdChannelNamesQEMU {
		var view unix.Statx_t
		if unix.Statx(unix.AT_FDCWD, root+"/root/proc/net/rpc/"+name+"/channel", 0, mask, &view) != nil || view.Mask&mask != mask {
			return ErrMismatch
		}
		original := channels.metadata[index+1]
		if view.Ino != original.Ino || view.Dev_major != original.Dev_major || view.Dev_minor != original.Dev_minor || view.Mode != original.Mode {
			return ErrMismatch
		}
		matches := 0
		for _, entry := range fds {
			var opened unix.Statx_t
			err := unix.Statx(unix.AT_FDCWD, root+"/fd/"+entry.Name(), 0, mask, &opened)
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if err != nil || opened.Mask&mask != mask {
				return ErrMismatch
			}
			if !sameMountdChannelQEMU(opened, view) {
				continue
			}
			info, err := nfsRPCBindReadQEMU(root + "/fdinfo/" + entry.Name())
			if err != nil {
				return err
			}
			seen := false
			for _, line := range strings.Split(string(info), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "flags:" {
					flags, err := strconv.ParseUint(fields[1], 8, 64)
					if err != nil || seen || flags&unix.O_PATH != 0 || flags&unix.O_ACCMODE != unix.O_RDWR {
						return ErrMismatch
					}
					seen = true
				}
			}
			if !seen {
				return ErrMismatch
			}
			matches++
		}
		if matches != 1 {
			return ErrMismatch
		}
	}
	return nil
}

// Caller holds the original NFS input gate and keeps the original rpcbind live
// through mountd's registration/unregistration and complete normal settlement.
func probeNFSMountdQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, bootstrap *os.File, rpcbind nfsCompanionQEMU) (result error) {
	if s == nil {
		return ErrInvalid
	}
	phase := "channels"
	var channels *NFSMountdChannelsQEMU
	var daemon *nfsDaemonQEMU
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsMountdRetainedQEMU = struct {
				channels *NFSMountdChannelsQEMU
				daemon   *nfsDaemonQEMU
				err      error
			}{channels, daemon, result}
			if !nfsSourceLossExpectedQEMU(s, result) {
				fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_MOUNTD_FAILURE phase=%s\n", phase)
			}
		}
	}()
	if s.review || s.closed || s.revalidate(ctx) != nil {
		return ErrReviewRequired
	}
	if inode, err := nfsRPCListenerQEMU(true); err != nil || inode != "" {
		return errors.Join(ErrMismatch, err)
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	if s.sourceAccess != nil {
		channels = s.sourceAccess.channels
	} else {
		channels, err = NewNFSMountdChannelsQEMU(ctx)
	}
	if err != nil {
		return err
	}
	copyChannels := *channels
	if copyChannels.Check(ctx) != ErrInvalid || copyChannels.Close() != ErrInvalid {
		return ErrMismatch
	}
	phase = "construct"
	daemon, err = newNFSDaemonQEMU(ctx, s, bootstrap, channels, true)
	if err != nil {
		return err
	}
	if s.revalidate(ctx) != nil || channels.Check(ctx) != nil {
		return ErrMismatch
	}
	phase = "start"
	nfsMountdUnsettledQEMU = true
	if err := daemon.start(ctx); err != nil {
		return err
	}
	copyDaemon := *daemon
	if copyDaemon.start(ctx) == nil || copyDaemon.check(ctx) == nil || copyDaemon.stop(ctx) == nil || copyDaemon.close() == nil ||
		daemon.start(ctx) == nil || daemon.close() == nil {
		return ErrMismatch
	}
	checkErr := func() error {
		phase = "ready"
		if err := daemon.check(ctx); err != nil {
			return err
		}
		phase = "kernel-composition"
		return probeNFSDKernelQEMU(ctx, s, channels, [2]nfsCompanionQEMU{rpcbind, {daemon.child, daemon.pid}})
	}()
	checkPhase := phase
	if nfsKernelUnsettledQEMU {
		return errors.Join(ErrReviewRequired, checkErr)
	} // The kernel may still consume its original mountd/rpcbind inputs.
	phase = "stop"
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := daemon.stop(cleanup)
	cancel()
	if stopErr != nil {
		return errors.Join(ErrReviewRequired, checkErr, stopErr)
	}
	nfsMountdUnsettledQEMU = false
	if checkErr != nil {
		phase = checkPhase
		return checkErr
	}
	if !errors.Is(daemon.close(), ErrUnavailable) {
		return ErrMismatch
	}
	if err := daemon.checkStopped(ctx); err != nil {
		return err
	}
	if daemon.stop(ctx) == nil {
		return ErrMismatch
	}
	phase = "normal-close"
	if err := daemon.close(); err != nil {
		return err
	}
	daemon = nil
	if channels.Check(ctx) != nil || s.revalidate(ctx) != nil {
		return ErrMismatch
	}
	if s.sourceAccess == nil {
		if err := channels.Close(); err != nil {
			return err
		}
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return ErrMismatch
	}
	// NULL RPC does not publish exports or modify mutable NFS tables.
	entries, err := os.ReadDir(nfsStateViewQEMU + "/nfs")
	if err != nil || s.sourceAccess == nil && len(entries) != 0 {
		return errors.Join(ErrMismatch, err)
	}
	if s.sourceAccess != nil {
		fmt.Println("PHANTOWD_NFS_SOURCE_MOUNTD_READY original_channels=3 original_sources=3 filehandle_view=true private_view=true uid_gid=0 caps=dac-read-search listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only")
	} else {
		fmt.Println("PHANTOWD_NFS_MOUNTD_READY original_inputs=true original_channels=3 metadata_only_collector=true child_channels_rw=true private_view=true uid_gid=0 capabilities_zero=true listener_pid_bound=true null_rpc_v3=true stop_reaped=true listener_stopped=true fd_balance=true nfsd=true exports=false product=false scope=qemu-only")
	}
	return nil
}

func nfsMountdHandoffForInputsQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, child *processowner.PinnedSet, stopped bool) error {
	if s.sourceAccess != nil {
		if s.sourceAccess.accessComplete {
			return child.CheckNFSSourceMountdAccessHandoffQEMU(ctx, stopped)
		}
		return child.CheckNFSSourceMountdHandoffQEMU(ctx, stopped)
	}
	return child.CheckNFSMountdHandoffQEMU(ctx, stopped)
}

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
	var child *processowner.PinnedSet
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsMountdRetainedQEMU = struct {
				channels *NFSMountdChannelsQEMU
				child    *processowner.PinnedSet
				err      error
			}{channels, child, result}
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_MOUNTD_FAILURE phase=%s\n", phase)
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
	program := s.code.files["usr/sbin/rpc.mountd"]
	for _, alias := range s.code.plan.aliases {
		if alias.Path == "usr/sbin/rpc.mountd" {
			program = s.code.files[alias.Target]
		}
	}
	if program == nil {
		return ErrMismatch
	}
	phase = "construct"
	spec := processowner.MemberSpec{Name: "nfs-mountd", Process: processowner.Spec{
		Executable: "/usr/sbin/phantowd-nfs-table-bootstrap", Args: []string{"mountd-v1"}, RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready: func(ctx context.Context) (bool, error) { return nfsRPCNullQEMU(ctx, true) }, ReadyTimeout: 5 * time.Second, ProbeInterval: 20 * time.Millisecond, StopTimeout: time.Second,
	}}
	if s.sourceAccess != nil {
		a := s.sourceAccess
		spec.Name = "nfs-source-mountd"
		spec.Process.Args = []string{"mountd-source-v1"}
		child, err = processowner.NewNFSSourceMountdPinnedQEMU(spec, bootstrap, [4]*os.File{s.code.root, s.configuration.contents.root, s.state.root, program}, [4]*os.File{channels.files[0], channels.files[1], channels.files[2], channels.namespaces[0]}, [6]*os.File{a.data[0], a.data[1], a.data[2], a.filehandle, a.features, a.volume})
	} else {
		child, err = processowner.NewNFSMountdPinnedQEMU(spec, bootstrap, [4]*os.File{s.code.root, s.configuration.contents.root, s.state.root, program}, [4]*os.File{channels.files[0], channels.files[1], channels.files[2], channels.namespaces[0]})
	}
	if err != nil {
		return err
	}
	if s.revalidate(ctx) != nil || channels.Check(ctx) != nil {
		return ErrMismatch
	}
	phase = "start"
	nfsMountdUnsettledQEMU = true
	started, err := child.Start(ctx)
	if err != nil {
		return err
	}
	pid := 0
	if len(started.Members) == 1 {
		pid = started.Members[0].Process.PID
	}
	checkErr := func() error {
		phase = "ready-handoff"
		if started.State != processowner.StateReady || started.Generation != 1 || len(started.Members) != 1 || pid <= 0 || started.Members[0].Process.DiagnosticsTruncated || nfsMountdHandoffForInputsQEMU(ctx, s, child, false) != nil {
			return ErrMismatch
		}
		phase = "ready-listener"
		inode, err := nfsRPCListenerQEMU(true)
		if err != nil || inode == "" {
			return errors.Join(ErrMismatch, err)
		}
		phase = "ready-process"
		if err := nfsRPCProcessQEMU(pid, s, program, inode, true); err != nil {
			return err
		}
		phase = "ready-original-channels"
		if err := observeNFSMountdChannelsQEMU(pid, channels); err != nil {
			return err
		}
		if s.sourceAccess != nil {
			if err := s.sourceAccess.checkView(pid); err != nil {
				return err
			}
		}
		if channels.Check(ctx) != nil || s.revalidate(ctx) != nil {
			return ErrMismatch
		}
		phase = "ready-null-rpc"
		if ok, err := nfsRPCNullQEMU(ctx, true); err != nil || !ok {
			return errors.Join(ErrMismatch, err)
		}
		observed, err := child.Observe(ctx)
		if err != nil || observed.State != processowner.StateReady || len(observed.Members) != 1 || observed.Members[0].Process.PID != pid {
			return errors.Join(ErrMismatch, err)
		}
		phase = "kernel-composition"
		return probeNFSDKernelQEMU(ctx, s, channels, [2]nfsCompanionQEMU{rpcbind, {child, pid}})
	}()
	checkPhase := phase
	if nfsKernelUnsettledQEMU {
		return errors.Join(ErrReviewRequired, checkErr)
	} // The kernel may still consume its original mountd/rpcbind inputs.
	phase = "stop"
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopped, stopErr := child.Stop(cleanup)
	cancel()
	if stopErr != nil || stopped.State != processowner.StateStopped || stopped.Generation != 1 || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 || stopped.Members[0].Process.DiagnosticsTruncated || pid <= 0 || !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.Join(ErrReviewRequired, checkErr, stopErr)
	}
	nfsMountdUnsettledQEMU = false
	if checkErr != nil {
		phase = checkPhase
		return checkErr
	}
	if inode, err := nfsRPCListenerQEMU(true); err != nil || inode != "" {
		return errors.Join(ErrMismatch, err)
	}
	if nfsMountdHandoffForInputsQEMU(ctx, s, child, true) != nil {
		return ErrMismatch
	}
	phase = "normal-close"
	if err := child.Close(); err != nil {
		return err
	}
	child = nil
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

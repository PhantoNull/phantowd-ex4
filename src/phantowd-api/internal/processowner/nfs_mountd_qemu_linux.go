//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// NewNFSMountdPinnedQEMU fixes three original metadata-only kernel channel
// references and their network namespace, in addition to the four NFS roles.
// Only the containing trusted lifetime grants the fixed fixture consumer use.
func NewNFSMountdPinnedQEMU(spec MemberSpec, bootstrap *os.File, objects [4]*os.File, channels [4]*os.File) (*PinnedSet, error) {
	c := spec.Process.RunAs
	if !nfsRuntimeFixtureGuardQEMU() || spec.Name != "nfs-mountd" || spec.Process.Executable != "/usr/sbin/phantowd-nfs-table-bootstrap" ||
		len(spec.Process.Args) != 1 || spec.Process.Args[0] != "mountd-v1" || c == nil || c.UID != 0 || c.GID != 0 || len(c.SupplementaryGIDs) != 0 ||
		spec.Process.ReadyTimeout != 5*time.Second || spec.Process.ProbeInterval != 20*time.Millisecond || spec.Process.StopTimeout != time.Second {
		return nil, ErrInvalid
	}
	s, err := newNFSFixedDaemonQEMU(spec, bootstrap, objects, channels[:])
	if err != nil {
		return nil, err
	}
	owner := s.set.members[0].owner
	probe := s.set.members[0].spec.Ready
	s.set.members[0].spec.Ready = func(ctx context.Context) (bool, error) {
		// Diagnostics is independently synchronized. Do not reenter the Set or
		// Owner lifecycle gates from its own readiness callback.
		complete, err := NFSMountdStartupReadyQEMU(owner.Diagnostics())
		if err != nil || !complete {
			return false, err
		}
		return probe(ctx)
	}
	return s, nil
}

func duplicateNFSKernelInputQEMU(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(value uintptr) { fd, dupErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || dupErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	return os.NewFile(uintptr(fd), "fixed-nfs-kernel-input"), nil
}

func nfsKernelInputQEMU(file *os.File, namespace bool) bool {
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	var fs unix.Statfs_t
	var st unix.Stat_t
	if err != nil || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Uid != 0 || st.Gid != 0 {
		return false
	}
	if namespace {
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		return err == nil && kind == unix.CLONE_NEWNET && fs.Type == unix.NSFS_MAGIC && flags&unix.O_PATH == 0 && flags&unix.O_ACCMODE == unix.O_RDONLY
	}
	return fs.Type == unix.PROC_SUPER_MAGIC && flags&unix.O_PATH != 0 && st.Mode == unix.S_IFREG|0600
}

func (s *PinnedSet) CheckNFSMountdHandoffQEMU(ctx context.Context, stopped bool) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	wanted := nfsMountdStartupQEMU
	if stopped {
		wanted += "rpc.mountd: Caught signal 15, un-registering and exiting.\n"
	}
	if len(s.pins) != 9 || len(s.set.members) != 1 || s.set.members[0].name != "nfs-mountd" || string(s.set.members[0].owner.Diagnostics()) != wanted {
		return ErrInvalid
	}
	return nil
}

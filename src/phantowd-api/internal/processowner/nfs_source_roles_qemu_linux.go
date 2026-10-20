//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type NFSSourceExportOperationQEMU string

const (
	NFSSourceActivateQEMU NFSSourceExportOperationQEMU = "exportfs-source-v1"
	NFSSourceWithdrawQEMU NFSSourceExportOperationQEMU = "withdraw-source-v1"
	NFSSourceFlushQEMU    NFSSourceExportOperationQEMU = "flush-source-v1"
)

// Cleanup-only ABI: no data root, volume anchor, filehandle or activation role.
type NFSWithdrawalOperationQEMU string

const (
	NFSWithdrawOwnedQEMU NFSWithdrawalOperationQEMU = "withdraw-owned-v1"
	NFSFlushOwnedQEMU    NFSWithdrawalOperationQEMU = "flush-owned-v1"
)

func NewNFSWithdrawalCaptureQEMU(role NFSWithdrawalOperationQEMU, bootstrap, input *os.File, objects [4]*os.File, extra [6]*os.File) (*CaptureOwner, error) {
	if !nfsSourceFixtureGuardQEMU() || (role != NFSWithdrawOwnedQEMU && role != NFSFlushOwnedQEMU) {
		return nil, ErrInvalid
	}
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil || !nfsSourceCleanupCommandQEMU(command) {
		return nil, ErrInvalid
	}
	return newNFSOwnedWithdrawalCaptureQEMU(string(role), bootstrap, input, objects, extra)
}

// A distinct fixed server-cleanup ABI. Both fault selectors reject sibling or
// unknown NFS flags; no caller chooses arguments, privileges or source roots.
func NewNFSServerWithdrawalCaptureQEMU(role NFSWithdrawalOperationQEMU, bootstrap, input *os.File, objects [4]*os.File, extra [6]*os.File) (*CaptureOwner, error) {
	if !nfsServerPeerFaultGuardQEMU() {
		return nil, ErrInvalid
	}
	var abi string
	switch role {
	case NFSWithdrawOwnedQEMU:
		abi = "withdraw-server-v1"
	case NFSFlushOwnedQEMU:
		abi = "flush-server-v1"
	default:
		return nil, ErrInvalid
	}
	return newNFSOwnedWithdrawalCaptureQEMU(abi, bootstrap, input, objects, extra)
}

func newNFSOwnedWithdrawalCaptureQEMU(role string, bootstrap, input *os.File, objects [4]*os.File, extra [6]*os.File) (*CaptureOwner, error) {
	return newNFSCommandCaptureQEMU(bootstrap, input, objects, role, extra[:], func(file *os.File, index int) bool {
		if index == 0 {
			return nfsSourceObjectQEMU(file, 4)
		}
		return nfsKernelInputQEMU(file, index == 5)
	})
}

func nfsSourceFixtureGuardQEMU() bool {
	if !nfsRuntimeFixtureGuardQEMU() {
		return false
	}
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(command) > 4096 {
		return false
	}
	count := 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_source_fixture=1" {
			count++
		}
	}
	return count == 1
}

// Three ORIGINAL O_PATH source directories, filehandle/export_features, and the
// ORIGINAL qualified volume root (attached read-only as the mountpoint anchor).
// The containing source/input Owner, not these shape checks, supplies provenance.
func NewNFSSourceMountdPinnedQEMU(spec MemberSpec, bootstrap *os.File, objects [4]*os.File, channels [4]*os.File, sources [6]*os.File) (*PinnedSet, error) {
	c := spec.Process.RunAs
	if !nfsSourceFixtureGuardQEMU() || spec.Name != "nfs-source-mountd" || spec.Process.Executable != "/usr/sbin/phantowd-nfs-table-bootstrap" ||
		len(spec.Process.Args) != 1 || spec.Process.Args[0] != "mountd-source-v1" || c == nil || c.UID != 0 || c.GID != 0 || len(c.SupplementaryGIDs) != 0 ||
		spec.Process.ReadyTimeout != 5*time.Second || spec.Process.ProbeInterval != 20*time.Millisecond || spec.Process.StopTimeout != time.Second {
		return nil, ErrInvalid
	}
	extra := append(append([]*os.File{}, channels[:]...), sources[:]...)
	s, err := newNFSFixedDaemonInputsQEMU(spec, bootstrap, objects, extra, func(file *os.File, index int) bool {
		if index < 4 {
			return nfsKernelInputQEMU(file, index == 3)
		}
		return nfsSourceObjectQEMU(file, index-4)
	})
	if err != nil {
		return nil, err
	}
	owner, probe := s.set.members[0].owner, s.set.members[0].spec.Ready
	s.set.members[0].spec.Ready = func(ctx context.Context) (bool, error) {
		ready, err := NFSSourceMountdStartupReadyQEMU(owner.Diagnostics())
		if err != nil || !ready {
			return false, err
		}
		return probe(ctx)
	}
	return s, nil
}

func (s *PinnedSet) CheckNFSSourceMountdHandoffQEMU(ctx context.Context, stopped bool) error {
	return s.checkNFSSourceMountdHandoffQEMU(ctx, stopped, false)
}

func (s *PinnedSet) CheckNFSSourceMountdAccessHandoffQEMU(ctx context.Context, stopped bool) error {
	return s.checkNFSSourceMountdHandoffQEMU(ctx, stopped, true)
}

func (s *PinnedSet) checkNFSSourceMountdHandoffQEMU(ctx context.Context, stopped, accessed bool) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	wanted := nfsSourceMountdStartupQEMU
	if stopped {
		wanted += "rpc.mountd: Caught signal 15, un-registering and exiting.\n"
	}
	if len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "nfs-source-mountd" {
		return ErrInvalid
	}
	data := s.set.members[0].owner.Diagnostics()
	if accessed {
		return NFSSourceMountdAccessHandoffQEMU(data, stopped)
	}
	if string(data) != wanted {
		return ErrInvalid
	}
	return nil
}

// ABI after original code/config/state/program: data[3], readonly features,
// flush[4], original network namespace, original readonly volume anchor.
// No filehandle or general proc grant.
func NewNFSSourceExportCaptureQEMU(role NFSSourceExportOperationQEMU, bootstrap, input *os.File, objects [4]*os.File, extra [10]*os.File) (*CaptureOwner, error) {
	if !nfsSourceFixtureGuardQEMU() || (role != NFSSourceActivateQEMU && role != NFSSourceWithdrawQEMU && role != NFSSourceFlushQEMU) {
		return nil, ErrInvalid
	}
	return newNFSCommandCaptureQEMU(bootstrap, input, objects, string(role), extra[:], func(file *os.File, index int) bool {
		switch {
		case index < 3:
			return nfsSourceObjectQEMU(file, index)
		case index == 3:
			return nfsSourceObjectQEMU(file, 4)
		case index < 8:
			return nfsKernelInputQEMU(file, false)
		case index == 9:
			return nfsSourceObjectQEMU(file, 5)
		default:
			return nfsKernelInputQEMU(file, true)
		}
	})
}

func nfsSourceObjectQEMU(file *os.File, index int) bool {
	var st unix.Stat_t
	var fs unix.Statfs_t
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil {
		return false
	}
	if index == 5 {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0 && st.Uid == 0 && st.Gid == 0 && fs.Type == unix.EXT4_SUPER_MAGIC && fs.Flags&unix.ST_RDONLY == 0
	}
	if index < 3 {
		return st.Mode == unix.S_IFDIR|0700 && st.Uid == 1000 && st.Gid == 1000 && fs.Type == unix.EXT4_SUPER_MAGIC &&
			fs.Flags&(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) == unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC
	}
	mode := uint32(unix.S_IFREG | 0600)
	if index == 4 {
		mode = unix.S_IFREG | 0444
	}
	return st.Mode == mode && st.Uid == 0 && st.Gid == 0 && fs.Type == 0x6e667364
}

func nfsSourceStatQEMU(file *os.File, st *unix.Statx_t) error {
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, st); err != nil || st.Mask&mask != mask {
		return ErrInvalid
	}
	return nil
}

func nfsSourceSameStatQEMU(a, b unix.Statx_t) bool {
	return a.Ino == b.Ino && a.Mnt_id == b.Mnt_id && a.Dev_major == b.Dev_major && a.Dev_minor == b.Dev_minor && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

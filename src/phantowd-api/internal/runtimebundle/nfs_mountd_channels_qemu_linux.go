//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

var nfsMountdChannelNamesQEMU = [...]string{"auth.unix.ip", "nfsd.export", "nfsd.fh"}

// NFSMountdChannelsQEMU retains metadata-only O_PATH references, never reads
// or writes a kernel channel. It is not sole-writer/NFSD/policy authority.
// The containing consumer must be absent before explicit normal Close.
type NFSMountdChannelsQEMU struct {
	original       *NFSMountdChannelsQEMU
	gate           chan struct{}
	root           *os.File
	files          [3]*os.File
	metadata       [4]unix.Statx_t
	namespaces     [2]*os.File
	ns             [2]unix.Stat_t
	closed, review bool
}

func NewNFSMountdChannelsQEMU(ctx context.Context) (_ *NFSMountdChannelsQEMU, result error) {
	if ctx == nil || nfsCodeGuardQEMU() != nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	o := &NFSMountdChannelsQEMU{gate: make(chan struct{}, 1)}
	o.original = o
	defer func() {
		if result != nil {
			result = constructionRollback(result, o, o.release)
		}
	}()
	for index, name := range []string{"net", "mnt"} {
		fd, err := unix.Open("/proc/thread-self/ns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		o.namespaces[index] = os.NewFile(uintptr(fd), "nfs-original-cache-namespace")
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		wanted := unix.CLONE_NEWNET
		if index == 1 {
			wanted = unix.CLONE_NEWNS
		}
		var fs unix.Statfs_t
		if err != nil || kind != wanted || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &o.ns[index]) != nil {
			return nil, ErrMismatch
		}
	}
	fd, err := unix.Open("/proc/thread-self/net/rpc", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	o.root = os.NewFile(uintptr(fd), "nfs-original-rpc-directory")
	if err := mountdChannelStatQEMU(fd, true, &o.metadata[0]); err != nil {
		return nil, err
	}
	for index, name := range nfsMountdChannelNamesQEMU {
		fd, err := unix.Openat2(int(o.root.Fd()), name+"/channel", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return nil, err
		}
		o.files[index] = os.NewFile(uintptr(fd), "nfs-original-cache-channel")
		if err := mountdChannelStatQEMU(fd, false, &o.metadata[index+1]); err != nil {
			return nil, err
		}
		if o.metadata[index+1].Mnt_id != o.metadata[0].Mnt_id {
			return nil, ErrMismatch
		}
	}
	if err := o.check(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func mountdChannelStatQEMU(fd int, directory bool, st *unix.Statx_t) error {
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	var fs unix.Statfs_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, st) != nil || st.Mask&mask != mask || st.Ino == 0 || st.Mnt_id == 0 || st.Uid != 0 || st.Gid != 0 {
		return ErrMismatch
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrMismatch
		}
	} else if st.Mode != unix.S_IFREG|0600 {
		return ErrMismatch
	}
	return nil
}

func (o *NFSMountdChannelsQEMU) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for index, name := range []string{"net", "mnt"} {
		var held, current unix.Stat_t
		if o.namespaces[index] == nil || unix.Fstat(int(o.namespaces[index].Fd()), &held) != nil || unix.Stat("/proc/thread-self/ns/"+name, &current) != nil || held.Dev != o.ns[index].Dev || held.Ino != o.ns[index].Ino || current.Dev != held.Dev || current.Ino != held.Ino {
			return ErrMismatch
		}
	}
	// PROC_ENTRY_FORCE_LOOKUP is inherited by every descendant of /proc/PID/net.
	// Reopening even a channel BENEATH the retained root invalidates the original
	// dentry ancestry and makes detached channel mounts fail in d_set_mounted.
	// Check retained namespace/root/channel metadata, never rewalk those names.
	// This does not prove a fresh named registry or sole-writer/kernel authority.
	for index, file := range append([]*os.File{o.root}, o.files[:]...) {
		var current unix.Statx_t
		if file == nil || mountdChannelStatQEMU(int(file.Fd()), index == 0, &current) != nil || !sameMountdChannelQEMU(current, o.metadata[index]) {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

func sameMountdChannelQEMU(a, b unix.Statx_t) bool {
	return a.Ino == b.Ino && a.Mnt_id == b.Mnt_id && a.Dev_major == b.Dev_major && a.Dev_minor == b.Dev_minor && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

func (o *NFSMountdChannelsQEMU) enter(ctx context.Context) error {
	if o == nil || o.original != o || o.gate == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
		runtime.LockOSThread()
		return nil
	default:
		return processowner.ErrBusy
	}
}
func (o *NFSMountdChannelsQEMU) leave() { runtime.UnlockOSThread(); <-o.gate }
func (o *NFSMountdChannelsQEMU) Check(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.leave()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return ErrUnavailable
	}
	if err := o.check(ctx); err != nil {
		o.review = true
		return ErrReviewRequired
	}
	return nil
}
func (o *NFSMountdChannelsQEMU) Close() error {
	if err := o.enter(context.Background()); err != nil {
		return err
	}
	defer o.leave()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return nil
	}
	if o.check(context.Background()) != nil || o.release() != nil {
		o.review = true
		return ErrReviewRequired
	}
	o.closed = true
	return nil
}
func (o *NFSMountdChannelsQEMU) release() error {
	for index, file := range o.files {
		if file != nil {
			if err := file.Close(); err != nil {
				return err
			}
			o.files[index] = nil
		}
	}
	if o.root != nil {
		if err := o.root.Close(); err != nil {
			return err
		}
		o.root = nil
	}
	for index, file := range o.namespaces {
		if file != nil {
			if err := file.Close(); err != nil {
				return err
			}
			o.namespaces[index] = nil
		}
	}
	return nil
}
func (NFSMountdChannelsQEMU) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NFSMountdChannelsQEMU) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (NFSMountdChannelsQEMU) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-mountd-channels{private}")
}

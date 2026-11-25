// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

const kernelLockName = ".phantowd-nfs-kernel.lock"

// OpenLinux retains the exact NFSD mount and namespaces granted by a platform
// owner. The caller must establish that the mount was created in that network
// namespace and that cooperating runtimes use the same protected /run mount.
// It supplies an admitted unicast IPv4 endpoint. OpenLinux performs no mounts,
// starts no listeners and never changes namespaces.
func OpenLinux(ctx context.Context, directory, network, mounts *os.File, address netip.Addr) (_ *Controller, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		!address.Is4() || !address.IsGlobalUnicast() && !address.IsLoopback() {
		return nil, ErrRefused
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	k := &Controller{gate: make(chan struct{}, 1), socket: -1, address: address.As4(), phase: "grant"}
	k.original = k
	admitted := false
	defer func() {
		if admitted {
			return
		}
		for _, file := range []*os.File{k.directory, k.mounts, k.network, k.lock} {
			if file != nil {
				result = errors.Join(result, file.Close())
			}
		}
	}()
	var err error
	k.directory, err = cloneKernelGrant(directory)
	if err != nil {
		return nil, err
	}
	for index, grant := range []struct {
		provided *os.File
		retained **os.File
		kind     int
	}{{network, &k.network, unix.CLONE_NEWNET}, {mounts, &k.mounts, unix.CLONE_NEWNS}} {
		file, err := cloneKernelGrant(grant.provided)
		if err != nil {
			return nil, err
		}
		*grant.retained = file
		fd := int(file.Fd())
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		var fs unix.Statfs_t
		if err != nil || kind != grant.kind || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC ||
			unix.Fstat(fd, &k.ns[index]) != nil || k.ns[index].Ino == 0 {
			return nil, ErrRefused
		}
	}
	fd := int(k.directory.Fd())
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != 0x6e667364 ||
		nfsKernelStat(fd, "", unix.AT_EMPTY_PATH, &k.root) != nil || k.root.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 ||
		k.check(ctx) != nil {
		return nil, ErrRefused
	}
	k.lock, err = acquireKernelLock()
	if err != nil {
		return nil, err
	}
	kernelRetention.Lock()
	if kernelRetention.active == nil && len(kernelRetention.objects) == 0 {
		kernelRetention.active = k
		admitted = true
	}
	kernelRetention.Unlock()
	if !admitted {
		return nil, ErrRefused
	}
	k.phase = "admitted-profile"
	if err := k.profile(ctx, false); err != nil {
		return nil, err
	}
	return k, nil
}

func cloneKernelGrant(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrRefused
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	runtime.KeepAlive(file)
	if err != nil {
		return nil, ErrRefused
	}
	return os.NewFile(uintptr(fd), "nfs-linux-grant"), nil
}

func acquireKernelLock() (*os.File, error) {
	run, err := unix.Open("/run", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRefused
	}
	defer unix.Close(run)
	var dir unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(run, &dir) != nil || dir.Mode != unix.S_IFDIR|0755 || dir.Uid != 0 ||
		unix.Fstatfs(run, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, ErrRefused
	}
	fd, err := unix.Openat(run, kernelLockName, unix.O_WRONLY|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrRefused
	}
	lock := os.NewFile(uintptr(fd), "nfs-linux-reservation")
	if !checkKernelLock(lock) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.Join(ErrRefused, lock.Close())
	}
	return lock, nil
}

func checkKernelLock(lock *os.File) bool {
	var held, path unix.Stat_t
	return unix.Fstat(int(lock.Fd()), &held) == nil && held.Mode == unix.S_IFREG|0600 && held.Uid == 0 && held.Nlink == 1 &&
		unix.Lstat("/run/"+kernelLockName, &path) == nil && held.Dev == path.Dev && held.Ino == path.Ino
}

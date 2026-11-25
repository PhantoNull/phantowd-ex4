// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

func readRC0SambaLaunch() (_ []runtimebundle.SambaLaunchRole, result error) {
	file, err := takeStartupFile(3, unix.S_IFREG)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	return runtimebundle.ReadSambaLaunchDeclaration(file)
}

type rc0SambaMountRole struct {
	source *os.File
	path   string
	attrs  uint64
}

// Only a root supervisor may supply these fixed roles. FD 3 is the sealed
// share declaration. FD 4 is the verified
// configuration tree. FD 5 and 6 are its original persistent database roles.
// Individual service-share mounts follow in declaration order.
func runRC0SambaChild(ctx context.Context) (result error) {
	// Mount namespace, chroot and capabilities follow the calling thread.
	// This entry point must exec or exit without returning the thread to Go.
	runtime.LockOSThread()
	if developmentBrowserEnrollment || ctx == nil || ctx.Err() != nil || !rc0SambaChildContext() {
		return errRC0Review
	}
	shares, err := readRC0SambaLaunch()
	if err != nil {
		return fmt.Errorf("read launch declaration: %w", err)
	}
	code, err := openVerifiedRC0SambaCode(ctx)
	if err != nil {
		return fmt.Errorf("verify runtime code: %w", err)
	}
	defer func() { result = errors.Join(result, code.Close()) }()
	roles, err := takeRC0SambaMountRoles(code, shares)
	defer func() {
		for _, role := range roles {
			result = errors.Join(result, role.source.Close())
		}
	}()
	if err != nil {
		return fmt.Errorf("admit mount roles: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := composeRC0SambaRoot(roles); err != nil {
		return fmt.Errorf("compose isolated root: %w", err)
	}
	if err := restrictRC0SambaCapabilities(); err != nil {
		return fmt.Errorf("restrict capabilities: %w", err)
	}
	if err := unix.CloseRange(3, 0xffffffff, unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("close inherited descriptors on exec: %w", err)
	}
	return syscall.Exec("/usr/sbin/smbd",
		[]string{"smbd", "-F", "--no-process-group", "-s", "/etc/samba/smb.conf", "-l", "/state", "--debug-stdout"},
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"})
}

func rc0SambaChildContext() bool {
	pid := os.Getpid()
	parent := os.Getppid()
	groups, err := unix.Getgroups()
	var proc unix.Statfs_t
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || err != nil ||
		len(groups) != 0 || pid <= 1 || parent <= 1 || unix.Getpgrp() != pid || !safeRC0RunDirectory() ||
		unix.Statfs("/proc/self/ns", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return false
	}
	selfNS, selfErr := os.Stat("/proc/thread-self/ns/mnt")
	parentNS, parentErr := os.Stat("/proc/" + strconv.Itoa(parent) + "/ns/mnt")
	return selfErr == nil && parentErr == nil && os.SameFile(selfNS, parentNS) && os.Getppid() == parent
}

func takeRC0SambaMountRoles(code *os.File, shares []runtimebundle.SambaLaunchRole) ([]rc0SambaMountRole, error) {
	const protected = unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV
	const data = protected | unix.MOUNT_ATTR_NOEXEC
	const immutable = protected | unix.MOUNT_ATTR_RDONLY
	var roles []rc0SambaMountRole
	for _, path := range []string{"lib", "usr"} {
		dir, err := openRC0Role(code, path, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return roles, err
		}
		roles = append(roles, rc0SambaMountRole{dir, path, immutable})
	}
	config, err := takeStartupFile(4, unix.S_IFDIR)
	if err != nil {
		return roles, err
	}
	roles = append(roles, rc0SambaMountRole{config, "etc", immutable | unix.MOUNT_ATTR_NOEXEC})
	if err := checkRC0SambaConfiguration(config); err != nil {
		return roles, err
	}
	var persistent unix.Statx_t
	for index, name := range rc0SambaPersistentRoles {
		dir, err := takeStartupFile(5+index, unix.S_IFDIR)
		if err != nil {
			return roles, err
		}
		roles = append(roles, rc0SambaMountRole{dir, "state/" + name, data})
		identity, err := observeRC0SambaDirectory(dir)
		if err != nil || (index > 0 && (identity.Mnt_id != persistent.Mnt_id || identity.Ino == persistent.Ino)) {
			return roles, errRC0Review
		}
		persistent = identity
	}
	mounts := make(map[uint64]bool, len(shares))
	for i, share := range shares {
		dir, err := takeStartupFile(i+7, unix.S_IFDIR)
		if err != nil {
			return roles, err
		}
		attrs := uint64(data)
		if share.ReadOnly {
			attrs |= unix.MOUNT_ATTR_RDONLY
		}
		roles = append(roles, rc0SambaMountRole{dir, "shares/" + share.ID, attrs})
		mount, err := observeRC0SambaShare(dir, share.ReadOnly)
		if err != nil || mounts[mount] {
			return roles, errRC0Review
		}
		mounts[mount] = true
	}
	return roles, nil
}

func checkRC0SambaConfiguration(dir *os.File) error {
	fd := int(dir.Fd())
	var st unix.Stat_t
	var fs unix.Statfs_t
	const required = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|0755 || st.Uid != 0 || st.Gid != 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&required != required {
		return errRC0Review
	}
	return nil
}

func observeRC0SambaShare(dir *os.File, readOnly bool) (uint64, error) {
	fd := int(dir.Fd())
	flags, err := unix.FcntlInt(dir.Fd(), unix.F_GETFL, 0)
	var st unix.Statx_t
	var fs unix.Statfs_t
	const required = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if err != nil || flags&unix.O_PATH == 0 ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &st) != nil ||
		st.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || st.Mnt_id == 0 ||
		st.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || st.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&required != required ||
		(fs.Flags&unix.ST_RDONLY != 0) != readOnly {
		return 0, errRC0Review
	}
	return st.Mnt_id, nil
}

func composeRC0SambaRoot(roles []rc0SambaMountRole) (result error) {
	var clones []int
	defer func() {
		for _, fd := range clones {
			result = errors.Join(result, unix.Close(fd))
		}
	}()
	// Inherited descriptors refer to mounts in the supervisor's namespace.
	// Clone without submounts while the current thread shares that namespace.
	for _, role := range roles {
		fd, err := unix.OpenTree(int(role.source.Fd()), "", unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
		if err != nil {
			return fmt.Errorf("clone approved mount: %w", err)
		}
		clones = append(clones, fd)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	// Mask the original /run only in this private namespace. The new
	// filesystem and its names disappear when the process group exits.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mount propagation private: %w", err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=4m"); err != nil {
		return fmt.Errorf("mount temporary root: %w", err)
	}
	for _, name := range []string{"state/lock", "state/cache", "state/pid", "state/rpc"} {
		if err := os.MkdirAll(filepath.Join("/run", name), 0700); err != nil {
			return err
		}
	}
	// Samba resolves the internal IPC share against /tmp. It needs a
	// directory in the chroot and no writable path outside /state and shares.
	if err := os.Mkdir("/run/tmp", 0755); err != nil {
		return err
	}
	// The state bind remains writable when the root mount becomes read-only.
	if err := unix.Mount("/run/state", "/run/state", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind temporary state: %w", err)
	}
	if err := unix.Mount("", "/run/state", "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("restrict temporary state: %w", err)
	}
	for i, role := range roles {
		if err := attachRC0SambaMount(role, clones[i]); err != nil {
			return err
		}
	}
	if err := unix.Mount("", "/run", "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("seal temporary root: %w", err)
	}
	if err := unix.Chroot("/run"); err != nil {
		return err
	}
	return unix.Chdir("/")
}

func attachRC0SambaMount(role rc0SambaMountRole, detached int) error {
	target := filepath.Join("/run", role.path)
	var source, attached unix.Stat_t
	if err := unix.Fstat(int(role.source.Fd()), &source); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := unix.MoveMount(detached, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("attach approved mount: %w", err)
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV)
	if role.attrs&unix.MOUNT_ATTR_RDONLY != 0 {
		flags |= unix.MS_RDONLY
	}
	if role.attrs&unix.MOUNT_ATTR_NOEXEC != 0 {
		flags |= unix.MS_NOEXEC
	}
	if err := unix.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("restrict approved mount: %w", err)
	}
	var fs unix.Statfs_t
	if unix.Lstat(target, &attached) != nil || source.Dev != attached.Dev || source.Ino != attached.Ino ||
		attached.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Statfs(target, &fs) != nil ||
		(fs.Flags&unix.ST_RDONLY != 0) != (role.attrs&unix.MOUNT_ATTR_RDONLY != 0) ||
		(fs.Flags&unix.ST_NOEXEC != 0) != (role.attrs&unix.MOUNT_ATTR_NOEXEC != 0) ||
		fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV) != unix.ST_NOSUID|unix.ST_NODEV {
		return errRC0Review
	}
	return nil
}

func restrictRC0SambaCapabilities() error {
	const allowed = (1 << unix.CAP_CHOWN) | (1 << unix.CAP_DAC_OVERRIDE) | (1 << unix.CAP_FOWNER) |
		(1 << unix.CAP_FSETID) | (1 << unix.CAP_SETGID) | (1 << unix.CAP_SETUID) | (1 << unix.CAP_NET_BIND_SERVICE)
	if unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil ||
		unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0) != nil {
		return errRC0Review
	}
	for capability := uintptr(0); ; capability++ {
		present, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, capability, 0, 0, 0)
		if errors.Is(err, unix.EINVAL) && capability > unix.CAP_CHECKPOINT_RESTORE {
			break
		}
		if err != nil {
			return errRC0Review
		}
		keep := capability < 32 && uint32(allowed)&(1<<capability) != 0
		if keep && present != 1 || !keep && present == 1 && unix.Prctl(unix.PR_CAPBSET_DROP, capability, 0, 0, 0) != nil {
			return errRC0Review
		}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{{Effective: allowed, Permitted: allowed}}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.Capset(&header, &data[0]) != nil {
		return errRC0Review
	}
	var actual [2]unix.CapUserData
	if unix.Capget(&header, &actual[0]) != nil || actual != data {
		return errRC0Review
	}
	return nil
}

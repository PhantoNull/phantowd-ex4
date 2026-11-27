// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// The parent retains FD 4 from the original process's procfs root. Use that
// root directly so the status command sees the actual lock and session DBs.
func runRC0SambaStatus() (int, error) {
	runtime.LockOSThread()
	if developmentBrowserEnrollment || !rc0SambaChildContext() {
		return 64, fmt.Errorf("check status launch: %w", errRC0Review)
	}
	root, err := takeStartupFile(4, unix.S_IFDIR)
	if err != nil {
		return 65, fmt.Errorf("open status root: %w", err)
	}
	defer root.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	const flags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV
	if unix.Fstat(int(root.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0755 ||
		st.Uid != 0 || st.Gid != 0 || unix.Fstatfs(int(root.Fd()), &fs) != nil ||
		fs.Type != unix.TMPFS_MAGIC || fs.Flags&flags != flags {
		return 65, fmt.Errorf("check status root: %w", errRC0Review)
	}
	if err := checkRC0SambaStatusCode(root); err != nil {
		return 66, fmt.Errorf("check status code: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNET); err != nil {
		return 67, fmt.Errorf("isolate status worker: %w", err)
	}
	if err := unix.Fchdir(int(root.Fd())); err != nil {
		return 68, fmt.Errorf("enter status root: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return 68, fmt.Errorf("set status root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return 68, fmt.Errorf("set status working directory: %w", err)
	}
	if err := setRC0SambaCapabilities(0); err != nil {
		return 69, fmt.Errorf("drop status capabilities: %w", err)
	}
	if err := unix.CloseRange(3, 0xffffffff, unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return 69, fmt.Errorf("close status descriptors: %w", err)
	}
	return 70, syscall.Exec("/usr/bin/smbstatus",
		[]string{"smbstatus", "--json", "--fast", "-s", "/etc/samba/smb.conf"},
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"})
}

func checkRC0SambaStatusCode(root *os.File) error {
	image, err := os.Open("/")
	if err != nil {
		return err
	}
	defer image.Close()
	for _, path := range []string{"lib", "usr"} {
		source, err := openRC0Role(image, rc0SambaCodeBundle+"/root/"+path, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		mounted, err := openRC0Role(root, path, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return errors.Join(err, source.Close())
		}
		var want, have unix.Stat_t
		var wantFS, haveFS unix.Statfs_t
		sourceFD, mountFD := int(source.Fd()), int(mounted.Fd())
		err = errors.Join(unix.Fstat(sourceFD, &want), unix.Fstat(mountFD, &have),
			unix.Fstatfs(sourceFD, &wantFS), unix.Fstatfs(mountFD, &haveFS),
			source.Close(), mounted.Close())
		const flags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV
		if err != nil || want.Dev != have.Dev || want.Ino != have.Ino ||
			wantFS.Flags&unix.ST_RDONLY == 0 || haveFS.Flags&flags != flags {
			return errors.Join(errRC0Review, err)
		}
	}
	return nil
}

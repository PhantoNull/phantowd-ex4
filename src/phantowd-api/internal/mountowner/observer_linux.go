// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

type linuxObserver struct{}

func (linuxObserver) ObserveMount(path string) (mountguard.Expected, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return mountguard.Expected{}, err
	}
	defer unix.Close(fd)
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return mountguard.Expected{}, err
	}
	if st.Mask&(unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) !=
		(unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return mountguard.Expected{}, mountguard.ErrUnsupported
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return mountguard.Expected{}, err
	}
	return mountguard.Expected{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major,
		DeviceMinor: st.Dev_minor, FilesystemType: uint32(filesystem.Type),
		RequireWritable: filesystem.Flags&unix.ST_RDONLY == 0}, nil
}

func (linuxObserver) ObserveTarget(path string) (TargetIdentity, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return TargetIdentity{}, err
	}
	defer unix.Close(fd)
	return observeTargetFD(fd)
}

func observeTargetFD(fd int) (TargetIdentity, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE|unix.STATX_BASIC_STATS, &st); err != nil {
		return TargetIdentity{}, err
	}
	const required = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if st.Mask&required != required || st.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return TargetIdentity{}, mountguard.ErrUnsupported
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return TargetIdentity{}, err
	}
	return TargetIdentity{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major,
		DeviceMinor: st.Dev_minor, FilesystemType: uint32(filesystem.Type),
		MountRoot: st.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0, MountRootKnown: true}, nil
}

func (linuxObserver) PinTarget(path string) (targetHandle, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	pin := &linuxTargetPin{file: os.NewFile(uintptr(fd), "mount-owner-target-pin")}
	if _, err := pin.Identity(); err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

type linuxTargetPin struct{ file *os.File }

func (p *linuxTargetPin) Identity() (TargetIdentity, error) {
	if p == nil || p.file == nil {
		return TargetIdentity{}, mountguard.ErrUnavailable
	}
	return observeTargetFD(int(p.file.Fd()))
}

func (p *linuxTargetPin) Empty() (bool, error) {
	if p == nil || p.file == nil {
		return false, mountguard.ErrUnavailable
	}
	fd, err := unix.Openat(int(p.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, mountguard.ErrUnavailable
	}
	directory := os.NewFile(uintptr(fd), "mount-owner-target-empty-check")
	defer directory.Close()
	entries, err := directory.ReadDir(1)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return false, mountguard.ErrUnavailable
	}
	return len(entries) == 0, nil
}

func (p *linuxTargetPin) File() *os.File {
	if p == nil {
		return nil
	}
	return p.file
}

func (p *linuxTargetPin) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

func openPath(path string, flags int) (int, error) {
	how := &unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return -1, mountguard.ErrUnavailable
	}
	return fd, nil
}

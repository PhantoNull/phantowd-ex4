//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	QEMUNativeVolumeID       = "qemu-native"
	QEMUNativeFilesystemUUID = "c395f03e-60ea-4ea1-9f47-08fb0aabfa72"
	qemuNativeSource         = "/run/phantowd-samba-source"
	qemuNativeTarget         = "/srv/phantowd/volumes/qemu-native"
)

// WithQEMUNativeMountedSet accepts only the fixed 16MiB ext4 image supplied by
// the Samba overlay in a disposable ARMv5 guest. No caller selects a path,
// device, UUID or compatibility rule. This is not a production roster provider.
func WithQEMUNativeMountedSet(inspect func(*MountedVolumeSet) error) error {
	if inspect == nil || runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrInvalid
	}
	commandLine, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") {
		return ErrInvalid
	}
	var fs unix.Statfs_t
	if unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs(qemuNativeSource, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC ||
		fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC {
		return ErrInvalid
	}
	size, err := os.ReadFile("/sys/block/sdb/size")
	var device, source unix.Stat_t
	if err != nil || strings.TrimSpace(string(size)) != "32768" ||
		unix.Lstat("/dev/sdb", &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK ||
		unix.Stat(qemuNativeSource, &source) != nil || source.Dev != device.Rdev {
		return ErrInvalid
	}
	// Read only the synthetic device's ext-family superblock, after every guest,
	// tmpfs, device-size and source/device binding guard above. Never write it.
	fd, err := unix.Open("/dev/sdb", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "fixed-qemu-native-ext4")
	var superblock [120]byte
	_, readErr := file.ReadAt(superblock[:], 1024)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	uuid := hex.EncodeToString(superblock[104:120])
	if superblock[56] != 0x53 || superblock[57] != 0xef || uuid != strings.ReplaceAll(QEMUNativeFilesystemUUID, "-", "") {
		return ErrInvalid
	}
	if err := os.MkdirAll("/srv/phantowd/volumes", 0755); err != nil {
		return err
	}
	// The fast overlay boots its original image read-only. Use only this fixed
	// volatile logical-anchor namespace; never remount the image writable.
	const anchors = "/srv/phantowd/volumes"
	original, err := nativeFixtureAnchorIdentityQEMU(anchors)
	var baseFS unix.Statfs_t
	rootIdentity, rootErr := nativeFixtureAnchorIdentityQEMU("/")
	if err != nil || rootErr != nil || original.Mnt_id != rootIdentity.Mnt_id ||
		unix.Statfs(anchors, &baseFS) != nil || baseFS.Type != unix.EXT4_SUPER_MAGIC || baseFS.Flags&unix.ST_RDONLY == 0 {
		return ErrInvalid
	}
	if err := unix.Mount("tmpfs", anchors, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		return err
	}
	volatile, err := nativeFixtureAnchorIdentityQEMU(anchors)
	if err != nil || volatile.Mnt_id == original.Mnt_id || !nativeFixtureVolatileAnchorQEMU(anchors) {
		return errors.Join(ErrReview, err) // Retain uncertain mounts; guest disposal is not recovery.
	}
	if err := withQEMUMountedOwnerAt(qemuNativeSource, qemuNativeTarget, QEMUNativeVolumeID,
		QEMUNativeFilesystemUUID, true, func(owner *Owner) error {
			set, err := newMountedVolumeSet([]string{QEMUNativeVolumeID}, []*Owner{owner})
			if err != nil {
				return err
			}
			return inspect(set)
		}); err != nil {
		return err // Do not detach after uncertain child mount/authority teardown.
	}
	current, err := nativeFixtureAnchorIdentityQEMU(anchors)
	if err != nil || current != volatile || !nativeFixtureVolatileAnchorQEMU(anchors) {
		return errors.Join(ErrReview, err)
	}
	if err := unix.Unmount(anchors, 0); err != nil {
		return err
	}
	current, err = nativeFixtureAnchorIdentityQEMU(anchors)
	if err != nil || current != original {
		return errors.Join(ErrReview, err)
	}
	return nil
}

func nativeFixtureVolatileAnchorQEMU(path string) bool {
	var fs unix.Statfs_t
	const protected = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	return unix.Statfs(path, &fs) == nil && fs.Type == unix.TMPFS_MAGIC &&
		fs.Flags&(protected|unix.ST_RDONLY) == protected
}

func nativeFixtureAnchorIdentityQEMU(path string) (unix.Statx_t, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return unix.Statx_t{}, err
	}
	defer unix.Close(fd)
	var identity unix.Statx_t
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &identity); err != nil ||
		identity.Mask&mask != mask || identity.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Statx_t{}, errors.Join(ErrInvalid, err)
	}
	// Compare stable mount/object identity only, not ctime/size changed by normal
	// creation/removal of this fixture's child anchor on volatile tmpfs.
	return unix.Statx_t{Mnt_id: identity.Mnt_id, Ino: identity.Ino,
		Dev_major: identity.Dev_major, Dev_minor: identity.Dev_minor}, nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const nativeDataBootstrapMarkerQEMU = "PHANTOWD_NATIVE_DATA_HANDOFF_READY inputs=14 original_config=true original_state=true original_shares=true individual_clones=true closed_before_exec=true scope=qemu-only\n"

// Mutable data roots are not immutable code/configuration. No hash, ctime,
// root ownership, exact mode or no-ACL restriction belongs to this admission.
// Validate the existing independent mount/RO role; never reopen a source path.
func duplicateNativeDataRootQEMU(source *os.File, readOnly bool) (_ *os.File, identity unix.Statx_t, result error) {
	if source == nil {
		return nil, identity, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, identity, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || duplicateErr != nil || fd < 0 {
		return nil, identity, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "original-native-share-input")
	defer func() {
		if result != nil {
			result = errors.Join(result, pin.Close())
		}
	}()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var fs unix.Statfs_t
	const protected = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	expected := int64(protected)
	if readOnly {
		expected |= unix.ST_RDONLY
	}
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstatfs(fd, &fs) != nil ||
		fs.Type != unix.EXT4_SUPER_MAGIC || int64(fs.Flags)&(protected|unix.ST_RDONLY) != expected ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &identity) != nil ||
		identity.Mask&mask != mask || identity.Mnt_id == 0 || identity.Mode&unix.S_IFMT != unix.S_IFDIR ||
		identity.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || identity.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return nil, identity, ErrInvalid
	}
	return pin, identity, nil
}

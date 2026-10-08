//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const nativeDataBootstrapMarkerQEMU = "PHANTOWD_NATIVE_DATA_HANDOFF_READY inputs=14 original_config=true original_state=true original_shares=true individual_clones=true closed_before_exec=true scope=qemu-only\n"

// VerifyNativeDataViewsQEMU compares only this set's owned, ready daemon with
// its retained original two roots. Clone mount IDs deliberately differ from
// source IDs; object identity and exact protected RO/RW roles must agree.
// No path, descriptor, data bytes or new lifecycle authority is returned.
func (s *PinnedSet) VerifyNativeDataViewsQEMU(ctx context.Context, pid int) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if pid <= 1 || len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "native-samba-data" {
		return ErrInvalid
	}
	observed, err := s.set.Observe(ctx)
	if err != nil || observed.State != StateReady || len(observed.Members) != 1 || observed.Members[0].Process.PID != pid {
		return errors.Join(ErrReviewRequired, err)
	}
	var identities [2]unix.Statx_t
	for index, name := range []string{"readonly", "writable"} {
		original := s.pins[13+index]
		if original == nil {
			return ErrInvalid
		}
		actual, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/root/shares/" + name)
		expected, expectedErr := original.Stat()
		var sourceFS, viewFS unix.Statfs_t
		const protected = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
		flags := int64(protected)
		if index == 0 {
			flags |= unix.ST_RDONLY
		}
		path := "/proc/" + strconv.Itoa(pid) + "/root/shares/" + name
		const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
		if err != nil || expectedErr != nil || !os.SameFile(actual, expected) || !actual.IsDir() ||
			unix.Fstatfs(int(original.Fd()), &sourceFS) != nil || unix.Statfs(path, &viewFS) != nil ||
			sourceFS.Type != unix.EXT4_SUPER_MAGIC || viewFS.Type != unix.EXT4_SUPER_MAGIC ||
			int64(sourceFS.Flags)&(protected|unix.ST_RDONLY) != flags || int64(viewFS.Flags)&(protected|unix.ST_RDONLY) != flags ||
			unix.Statx(unix.AT_FDCWD, path, unix.AT_NO_AUTOMOUNT, mask, &identities[index]) != nil ||
			identities[index].Mask&mask != mask || identities[index].Mnt_id == 0 ||
			identities[index].Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || identities[index].Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
			return ErrReviewRequired
		}
		if index == 1 && identities[0].Mnt_id == identities[1].Mnt_id {
			return ErrReviewRequired
		}
	}
	return ctx.Err()
}

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

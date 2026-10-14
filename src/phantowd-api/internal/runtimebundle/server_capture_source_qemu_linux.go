//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Fixed fixture leaf in the originally retained parent share. A pathname is
// not identity: its no-follow observation must match the held original object.
// No open/adoption, metadata refresh, write, request/OFD or recovery authority.
func recheckCaptureSourceQEMU(ctx context.Context, root, original *os.File, initial unix.Stat_t) error {
	if ctx == nil || root == nil || original == nil || initial.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var before, named, after unix.Stat_t
	if err := unix.Fstat(int(original.Fd()), &before); err != nil {
		return errors.Join(ErrMismatch, err)
	}
	if err := unix.Fstatat(int(root.Fd()), "capture-read", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errors.Join(ErrMismatch, err)
	}
	if err := unix.Fstat(int(original.Fd()), &after); err != nil {
		return errors.Join(ErrMismatch, err)
	}
	if !samePendingObjectQEMU(initial, before) || !samePendingObjectQEMU(initial, named) || !samePendingObjectQEMU(before, after) {
		return ErrMismatch
	}
	return ctx.Err()
}

// Fixed parent-visible share binding, observed beneath the retained root
// anchor. The temporary O_PATH descriptor is metadata only: never adopt it as
// a replacement share. Crossing the prepared mount is intentional; its unique
// original mount identity must match. Share ownership/flags remain separately
// enforced by the runtime's complete input fence.
func recheckCaptureShareBindingQEMU(ctx context.Context, anchor, root *os.File, expected serverObserverRootIdentityQEMU) error {
	if ctx == nil || anchor == nil || root == nil || expected.inode == 0 || expected.mount == 0 {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	identity := func(fd int) (serverObserverRootIdentityQEMU, error) {
		var stat unix.Statx_t
		const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
		if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &stat); err != nil {
			return serverObserverRootIdentityQEMU{}, errors.Join(ErrMismatch, err)
		}
		if stat.Mask&required != required || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Ino == 0 || stat.Mnt_id == 0 {
			return serverObserverRootIdentityQEMU{}, ErrMismatch
		}
		return serverObserverRootIdentityQEMU{stat.Dev_major, stat.Dev_minor, stat.Ino, stat.Mnt_id}, nil
	}
	before, err := identity(int(root.Fd()))
	if err != nil || before != expected {
		return errors.Join(ErrMismatch, err)
	}
	fd, err := unix.Openat2(int(anchor.Fd()), "run/observer-readonly", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return errors.Join(ErrMismatch, err)
	}
	named, statErr := identity(fd)
	closeErr := unix.Close(fd)
	after, afterErr := identity(int(root.Fd()))
	if statErr != nil || closeErr != nil || afterErr != nil || named != expected || after != expected {
		return errors.Join(ErrMismatch, statErr, closeErr, afterErr)
	}
	return ctx.Err()
}

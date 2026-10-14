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

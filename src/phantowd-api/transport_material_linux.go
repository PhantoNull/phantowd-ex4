// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func openTLSMaterialFile(path string) (*os.File, error) {
	// Require the kernel's whole-path no-symlink resolution, not an ancestry
	// lstat walk with a check/open race. No weaker fallback on older kernels or
	// a denied syscall. This does not retain parent or mount authority afterward.
	// Preserve Open's O_LARGEFILE addition for 32-bit ARM and the original
	// nonblocking FIFO, read-only and close-on-exec semantics.
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_LARGEFILE,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tls-startup-material"), nil
}

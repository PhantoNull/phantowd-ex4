// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func openTLSMaterialFile(path string) (*os.File, error) {
	// Nonblocking open prevents a substituted FIFO from stalling startup before
	// fstat. Leaf symlinks refuse at open, not just at the earlier lstat.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tls-startup-material"), nil
}

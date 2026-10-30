//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenDirectoryWithCodec borrows a trusted startup directory, retaining a new
// confined descriptor and independent lock. It does not transfer an old Owner
// or bootstrap epoch. The usual fresh-owner sync boundary remains unchanged.
func OpenDirectoryWithCodec[T any](directory *os.File, codec Codec[T]) (*Store[T], error) {
	if directory == nil || !codec.valid() {
		return nil, ErrUnsafe
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, ErrUnsafe
	}
	fd := -1
	var openErr error
	err = raw.Control(func(original uintptr) {
		var before, after unix.Stat_t
		if unix.Fstat(int(original), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFDIR {
			openErr = ErrUnsafe
			return
		}
		fd, openErr = unix.Openat2(int(original), ".", &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if openErr == nil && (unix.Fstat(fd, &after) != nil || policyStamp(before) != policyStamp(after)) {
			openErr = ErrUnsafe
		}
	})
	if err != nil || openErr != nil || fd < 0 {
		if fd >= 0 {
			unix.Close(fd)
		}
		return nil, ErrUnsafe
	}
	return openDescriptorWithCodec(fd, codec)
}

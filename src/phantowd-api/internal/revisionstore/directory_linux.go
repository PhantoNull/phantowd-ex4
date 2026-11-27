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
	if !codec.valid() {
		return nil, ErrUnsafe
	}
	fd, err := borrowDirectoryDescription(directory, 0)
	if err != nil {
		return nil, err
	}
	return openDescriptorWithCodec(fd, codec, false)
}

// OpenOwnedDirectoryWithCodec borrows the supplied directory independently
// and creates a fresh retained observation epoch. Fixed-name file reads stay
// on the original mount and use O_NOATIME throughout construction and use.
func OpenOwnedDirectoryWithCodec[T any](directory *os.File, codec Codec[T]) (*OwnedStore[T], error) {
	if !codec.valid() {
		return nil, ErrUnsafe
	}
	fd, err := borrowDirectoryDescription(directory, unix.O_NOATIME)
	if err != nil {
		return nil, err
	}
	s, err := openDescriptorWithCodec(fd, codec, true)
	if err != nil {
		return nil, err
	}
	return ownStore(s)
}

func borrowDirectoryDescription(directory *os.File, flags uint64) (int, error) {
	if directory == nil {
		return -1, ErrUnsafe
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return -1, ErrUnsafe
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
			Flags:   flags | unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
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
		return -1, ErrUnsafe
	}
	return fd, nil
}

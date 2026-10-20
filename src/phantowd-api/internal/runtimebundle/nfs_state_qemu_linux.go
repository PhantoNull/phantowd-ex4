//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Only fresh guest RAM is admitted. Mutable file contents/ctime are NOT
// immutable identity. This is not product state recovery or writer ownership.
type retainedNFSStateQEMU struct {
	root     *os.File
	files    map[string]*os.File
	identity map[string]nfsStateIdentityQEMU
	closeErr error
}

type nfsStateIdentityQEMU struct {
	inode, mount uint64
	major, minor uint32
}

var nfsStateDirectoriesQEMU = [...]string{".", "nfs"}

func inspectNFSStateQEMU(fd int) (nfsStateIdentityQEMU, error) {
	var st unix.Statx_t
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	var fs unix.Statfs_t
	const flags = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &st) != nil || st.Mask&mask != mask || st.Mnt_id == 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&flags != flags || fs.Flags&unix.ST_RDONLY != 0 ||
		st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || codeNoExtendedPermissions(fd) != nil {
		return nfsStateIdentityQEMU{}, ErrMismatch
	}
	return nfsStateIdentityQEMU{st.Ino, st.Mnt_id, st.Dev_major, st.Dev_minor}, nil
}

func retainNFSStateQEMU(ctx context.Context, root *os.File) (_ *retainedNFSStateQEMU, result error) {
	if ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	s := &retainedNFSStateQEMU{files: map[string]*os.File{}, identity: map[string]nfsStateIdentityQEMU{}}
	defer func() {
		if result != nil {
			result = constructionRollback(result, s, s.release)
		}
	}()
	var err error
	s.root, err = duplicateRoot(root)
	if err != nil {
		return nil, err
	}
	for _, name := range nfsStateDirectoriesQEMU {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := openBeneath(int(s.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		s.files[name] = os.NewFile(uintptr(fd), "nfs-original-mutable-directory")
		s.identity[name], err = inspectNFSStateQEMU(fd)
		if err != nil {
			return nil, err
		}
	}
	// Freshness is a fixture precondition, not inference of a pristine NAS.
	names, readErr := s.files["."].ReadDir(3)
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(names) != 1 || names[0].Name() != "nfs" || !names[0].IsDir() {
		return nil, ErrMismatch
	}
	// A nonempty ReadDir result can have nil error even at the end. Demand
	// the subsequent empty EOF explicitly; never infer completion from a short
	// successful read or mistake it for an invalid fresh directory.
	extra, finalErr := s.files["."].ReadDir(1)
	if !errors.Is(finalErr, io.EOF) || len(extra) != 0 {
		return nil, ErrMismatch
	}
	names, readErr = s.files["nfs"].ReadDir(1)
	if !errors.Is(readErr, io.EOF) || len(names) != 0 {
		return nil, ErrMismatch
	}
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *retainedNFSStateQEMU) revalidate(ctx context.Context) error {
	if s == nil || s.root == nil || len(s.files) != 2 || len(s.identity) != 2 || s.closeErr != nil {
		return ErrMismatch
	}
	for _, name := range nfsStateDirectoriesQEMU {
		if err := ctx.Err(); err != nil {
			return err
		}
		pin := s.files[name]
		if pin == nil {
			return ErrMismatch
		}
		original, err := inspectNFSStateQEMU(int(pin.Fd()))
		if err != nil || original != s.identity[name] || original.mount != s.identity["."].mount {
			return ErrMismatch
		}
		fd, err := openBeneath(int(s.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		current, inspectErr := inspectNFSStateQEMU(fd)
		closeErr := unix.Close(fd)
		if inspectErr != nil || closeErr != nil || current != original {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

func (s *retainedNFSStateQEMU) release() error {
	if s == nil {
		return nil
	}
	if s.closeErr != nil {
		return s.closeErr
	}
	for _, name := range nfsStateDirectoriesQEMU {
		if pin := s.files[name]; pin != nil {
			if err := pin.Close(); err != nil {
				s.closeErr = err
				return err
			}
			delete(s.files, name)
		}
	}
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			s.closeErr = err
			return err
		}
		s.root = nil
	}
	return nil
}

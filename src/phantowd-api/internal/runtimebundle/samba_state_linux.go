//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Mutable state has a different contract from immutable code/configuration.
// Retain its directory objects, not a checksum or timestamp of Samba's TDBs.
// Only the disposable Samba constructor currently consumes this private type.
// Its containing Owner must verify whole-group stop before releasing any pin.
type retainedSambaState struct {
	root     *os.File
	files    map[string]*os.File
	identity map[string]sambaStateIdentity
}

type sambaStateIdentity struct {
	deviceMajor, deviceMinor uint32
	inode, mount             uint64
}

var sambaStateDirectories = [...]string{".", "private", "lock", "state", "cache", "pid", "rpc"}

func retainSambaState(ctx context.Context, root *os.File) (*retainedSambaState, error) {
	if ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &retainedSambaState{files: make(map[string]*os.File, 7), identity: make(map[string]sambaStateIdentity, 7)}
	keep := false
	defer func() {
		if !keep {
			_ = s.release()
		}
	}()
	var err error
	s.root, err = duplicateRoot(root)
	if err != nil {
		return nil, err
	}
	for _, name := range sambaStateDirectories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := openBeneath(int(s.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		s.files[name] = os.NewFile(uintptr(fd), "retained-samba-state")
		s.identity[name], err = inspectSambaState(fd)
		if err != nil {
			return nil, err
		}
	}
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	keep = true
	return s, nil
}

func inspectSambaState(fd int) (sambaStateIdentity, error) {
	var st unix.Statx_t
	// Unlike the immutable code census, this private mutable-state tracer uses
	// the ordinary mount ID. The original open references retain that mount
	// during its lifetime; this is not an unretained identity or product grant.
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &st) != nil || st.Mask&required != required || st.Mnt_id == 0 {
		return sambaStateIdentity{}, ErrUnavailable
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil {
		return sambaStateIdentity{}, ErrUnavailable
	}
	if st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY != 0 || codeNoExtendedPermissions(fd) != nil {
		return sambaStateIdentity{}, ErrMismatch
	}
	return sambaStateIdentity{st.Dev_major, st.Dev_minor, st.Ino, st.Mnt_id}, nil
}

func (s *retainedSambaState) revalidate(ctx context.Context) error {
	if s == nil || s.root == nil || len(s.files) != 7 || len(s.identity) != 7 || ctx == nil {
		return ErrUnavailable
	}
	for _, name := range sambaStateDirectories {
		if err := ctx.Err(); err != nil {
			return err
		}
		pin := s.files[name]
		if pin == nil {
			return ErrMismatch
		}
		original, err := inspectSambaState(int(pin.Fd()))
		if err != nil || original != s.identity[name] || original.mount != s.identity["."].mount {
			return ErrMismatch
		}
		fd, err := openBeneath(int(s.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		current, inspectErr := inspectSambaState(fd)
		closeErr := unix.Close(fd)
		if inspectErr != nil || closeErr != nil || current != original {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

func (s *retainedSambaState) release() error {
	if s == nil {
		return nil
	}
	var result error
	for _, pin := range s.files {
		result = errors.Join(result, pin.Close())
	}
	s.files = nil
	s.identity = nil
	if s.root != nil {
		result = errors.Join(result, s.root.Close())
		s.root = nil
	}
	return result
}

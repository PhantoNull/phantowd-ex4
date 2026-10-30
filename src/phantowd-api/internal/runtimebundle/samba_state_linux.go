//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

// Mutable state has a different contract from immutable code/configuration.
// Retain its directory objects, not a checksum or timestamp of Samba's TDBs.
// Only the disposable Samba constructor currently consumes this private type.
// Its containing Owner must verify whole-group stop before releasing any pin.
type retainedSambaState struct {
	root               *os.File
	files              map[string]*os.File
	identity           map[string]sambaStateIdentity
	releaseErr         error
	persistent         *os.File
	persistentIdentity sambaStateIdentity
}

type sambaStateIdentity struct {
	deviceMajor, deviceMinor uint32
	inode, mount             uint64
}

var sambaStateDirectories = [...]string{".", "private", "lock", "state", "cache", "pid", "rpc"}

func retainSambaState(ctx context.Context, root *os.File) (*retainedSambaState, error) {
	return retainSambaStateRoots(ctx, root, nil)
}

func retainSambaStateRoots(ctx context.Context, root, persistent *os.File) (*retainedSambaState, error) {
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
	if persistent != nil {
		s.persistent, err = readableSambaRoot(persistent)
		if err != nil {
			return nil, err
		}
		s.persistentIdentity, err = inspectSambaStateKind(int(s.persistent.Fd()), true)
		if err != nil {
			return nil, err
		}
	}
	for _, name := range sambaStateDirectories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := openBeneath(int(s.sourceRoot(name).Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		s.files[name] = os.NewFile(uintptr(fd), "retained-samba-state")
		s.identity[name], err = inspectSambaStateKind(fd, s.persistentRole(name))
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

func readableSambaRoot(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var openErr error
	err = raw.Control(func(value uintptr) {
		fd, openErr = openBeneath(int(value), ".", unix.O_RDONLY|unix.O_DIRECTORY)
	})
	if err != nil || openErr != nil || fd < 0 {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, ErrMismatch
	}
	return os.NewFile(uintptr(fd), "retained-persistent-state-root"), nil
}

func inspectSambaState(fd int) (sambaStateIdentity, error) {
	return inspectSambaStateKind(fd, false)
}

func inspectSambaStateKind(fd int, persistent bool) (sambaStateIdentity, error) {
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
	kind := int64(unix.TMPFS_MAGIC)
	if persistent {
		kind = unix.EXT4_SUPER_MAGIC
	}
	if st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || int64(fs.Type) != kind || fs.Flags&unix.ST_RDONLY != 0 || codeNoExtendedPermissions(fd) != nil {
		return sambaStateIdentity{}, ErrMismatch
	}
	return sambaStateIdentity{st.Dev_major, st.Dev_minor, st.Ino, st.Mnt_id}, nil
}

func (s *retainedSambaState) revalidate(ctx context.Context) error {
	if s == nil || s.root == nil || len(s.files) != 7 || len(s.identity) != 7 || ctx == nil {
		return ErrUnavailable
	}
	if s.persistent != nil {
		actual, err := inspectSambaStateKind(int(s.persistent.Fd()), true)
		if err != nil || actual != s.persistentIdentity {
			return ErrMismatch
		}
	}
	for _, name := range sambaStateDirectories {
		if err := ctx.Err(); err != nil {
			return err
		}
		pin := s.files[name]
		if pin == nil {
			return ErrMismatch
		}
		expectedMount := s.identity["."].mount
		if s.persistentRole(name) {
			expectedMount = s.persistentIdentity.mount
		}
		original, err := inspectSambaStateKind(int(pin.Fd()), s.persistentRole(name))
		if err != nil || original != s.identity[name] || original.mount != expectedMount {
			return ErrMismatch
		}
		fd, err := openBeneath(int(s.sourceRoot(name).Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		current, inspectErr := inspectSambaStateKind(fd, s.persistentRole(name))
		closeErr := unix.Close(fd)
		if inspectErr != nil || closeErr != nil || current != original {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

func (s *retainedSambaState) persistentRole(name string) bool {
	return s.persistent != nil && (name == "private" || name == "state")
}
func (s *retainedSambaState) sourceRoot(name string) *os.File {
	if s.persistentRole(name) {
		return s.persistent
	}
	return s.root
}

// Never retry an uncertain close or continue to another input afterward.
// Confirmed earlier closures stay released; unattempted inputs remain retained.
func (s *retainedSambaState) release() error {
	if s == nil {
		return nil
	}
	if s.releaseErr != nil {
		return s.releaseErr
	}
	for name, pin := range s.files {
		if err := pin.Close(); err != nil {
			s.releaseErr = err
			return err
		}
		delete(s.files, name)
	}
	s.files = nil
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			s.releaseErr = err
			return err
		}
		s.root = nil
	}
	if s.persistent != nil {
		if err := s.persistent.Close(); err != nil {
			s.releaseErr = err
			return err
		}
		s.persistent = nil
	}
	s.identity = nil
	return nil
}

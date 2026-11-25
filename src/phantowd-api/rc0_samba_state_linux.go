// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const (
	rc0SambaStateRole  = "samba-state"
	rc0SambaStateStage = ".samba-state.provisioning"
)

var rc0SambaPersistentRoles = [...]string{"private", "state"}

type rc0SambaState struct {
	dir   *os.File
	roles [len(rc0SambaPersistentRoles)]*os.File
}

func provisionInheritedRC0SambaState(ctx context.Context) (result error) {
	if developmentBrowserEnrollment || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return provisionRC0SambaState(ctx, root)
}

// The caller holds the admitted state lock. The stage is durable before
// publication begins and any interrupted stage requires review.
func provisionRC0SambaState(ctx context.Context, root *os.File) (result error) {
	if _, err := observeRC0SambaDirectory(root); err != nil || ctx == nil || ctx.Err() != nil ||
		!rc0AbsentRole(root, rc0SambaStateStage) || !rc0AbsentRole(root, rc0SambaStateRole) {
		return errRC0Review
	}
	parentFD := int(root.Fd())
	if unix.Mkdirat(parentFD, rc0SambaStateStage, 0700) != nil || unix.Fsync(parentFD) != nil {
		return errRC0Review
	}
	stage, err := openRC0Role(root, rc0SambaStateStage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return errRC0Review
	}
	defer func() { result = errors.Join(result, stage.Close()) }()
	for _, role := range rc0SambaPersistentRoles {
		if err := unix.Mkdirat(int(stage.Fd()), role, 0700); err != nil {
			return errRC0Review
		}
	}
	dirs, err := retainRC0SambaState(root, rc0SambaStateStage)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, dirs.Close()) }()
	for _, dir := range dirs.roles {
		if err := unix.Fsync(int(dir.Fd())); err != nil {
			return errRC0Review
		}
	}
	original, err := observeRC0SambaDirectory(stage)
	if err != nil || !sameRC0SambaRole(root, rc0SambaStateStage, original) ||
		unix.Fsync(int(stage.Fd())) != nil || ctx.Err() != nil {
		return errRC0Review
	}
	if unix.Renameat2(parentFD, rc0SambaStateStage, parentFD, rc0SambaStateRole, unix.RENAME_NOREPLACE) != nil ||
		unix.Fsync(parentFD) != nil {
		return errRC0Review
	}
	return nil
}

func openRC0SambaState(root *os.File) (*rc0SambaState, error) {
	if !rc0AbsentRole(root, rc0SambaStateStage) {
		return nil, errRC0Review
	}
	return retainRC0SambaState(root, rc0SambaStateRole)
}

func retainRC0SambaState(root *os.File, name string) (_ *rc0SambaState, result error) {
	dir, err := openRC0Role(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if name == rc0SambaStateRole && errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, errRC0Review
	}
	state := &rc0SambaState{dir: dir}
	defer func() {
		if result != nil {
			result = errors.Join(result, state.Close())
		}
	}()
	_, err = observeRC0SambaDirectory(dir)
	if err != nil || unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errRC0Review
	}
	names, err := dir.Readdirnames(len(rc0SambaPersistentRoles) + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) != len(rc0SambaPersistentRoles) {
		return nil, errRC0Review
	}
	for i, role := range rc0SambaPersistentRoles {
		state.roles[i], err = openRC0Role(dir, role, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
		if err != nil {
			return nil, errRC0Review
		}
	}
	if err := state.check(root, name); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *rc0SambaState) check(parent *os.File, name string) error {
	original, err := observeRC0SambaDirectory(s.dir)
	if err != nil || !sameRC0SambaRole(parent, name, original) {
		return errRC0Review
	}
	for i, role := range rc0SambaPersistentRoles {
		observed, err := observeRC0SambaDirectory(s.roles[i])
		if err != nil || !sameRC0SambaRole(s.dir, role, observed) {
			return errRC0Review
		}
	}
	return nil
}

const rc0SambaDirMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID |
	unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE

func observeRC0SambaDirectory(dir *os.File) (unix.Statx_t, error) {
	var st unix.Statx_t
	var fs unix.Statfs_t
	if dir == nil {
		return st, errRC0Review
	}
	fd := int(dir.Fd())
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, rc0SambaDirMask, &st) != nil ||
		st.Mask&rc0SambaDirMask != rc0SambaDirMask || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&unix.ST_RDONLY != 0 {
		return st, errRC0Review
	}
	for _, acl := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if _, err := unix.Fgetxattr(fd, acl, nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return st, errRC0Review
		}
	}
	return st, nil
}

func sameRC0SambaRole(parent *os.File, name string, original unix.Statx_t) bool {
	var current unix.Statx_t
	return unix.Statx(int(parent.Fd()), name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, rc0SambaDirMask, &current) == nil &&
		current.Mask&rc0SambaDirMask == rc0SambaDirMask && current.Dev_major == original.Dev_major &&
		current.Dev_minor == original.Dev_minor && current.Mnt_id == original.Mnt_id &&
		current.Ino == original.Ino && current.Mode == original.Mode &&
		current.Uid == original.Uid && current.Gid == original.Gid
}

func (s *rc0SambaState) Close() error {
	var result error
	for i, dir := range s.roles {
		if dir != nil {
			result = errors.Join(result, dir.Close())
			s.roles[i] = nil
		}
	}
	return errors.Join(result, s.dir.Close())
}

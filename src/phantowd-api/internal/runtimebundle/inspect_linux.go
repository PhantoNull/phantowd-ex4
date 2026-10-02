//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path"
	"runtime"

	"golang.org/x/sys/unix"
)

// Inspect requires an O_PATH directory on a kernel-enforced read-only mount.
// It duplicates the root, refuses symlink traversal and cross-mount opens,
// checks the complete code-only census and hashes only declared regular files.
// It writes/mounts/launches nothing and returns no partial observation on error.
func (p *Plan) Inspect(ctx context.Context, root *os.File) (Observation, error) {
	if p == nil || len(p.files) == 0 || ctx == nil || root == nil {
		return Observation{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Observation{}, ctx.Err()
	}
	defer runtime.KeepAlive(root)
	fd, err := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	defer unix.Close(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || flags&unix.O_DIRECTORY == 0 {
		return Observation{}, ErrInvalid
	}
	initial, err := inspectMetadata(fd, unix.S_IFDIR, 0)
	if err != nil {
		return Observation{}, err
	}
	var original unix.Stat_t
	if unix.Stat("/", &original) != nil || (initial.Ino == original.Ino && initial.Dev_major == unix.Major(uint64(original.Dev)) && initial.Dev_minor == unix.Minor(uint64(original.Dev))) {
		return Observation{}, ErrInvalid
	}
	seen := make(map[string]bool, len(p.nodes))
	if err := p.census(ctx, fd, ".", initial.Mnt_id, seen); err != nil || len(seen) != len(p.nodes) {
		if err != nil {
			return Observation{}, err
		}
		return Observation{}, ErrMismatch
	}
	for _, alias := range p.aliases {
		parent, err := openBeneath(fd, path.Dir(alias.Path), unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return Observation{}, err
		}
		buffer := make([]byte, len(alias.Target)+2)
		count, readErr := unix.Readlinkat(parent, path.Base(alias.Path), buffer)
		_ = unix.Close(parent)
		if readErr != nil || count != len(alias.Target)+1 || string(buffer[:count]) != "/"+alias.Target {
			return Observation{}, ErrMismatch
		}
	}
	for _, file := range p.files {
		if err := inspectFile(ctx, fd, initial.Mnt_id, file); err != nil {
			return Observation{}, err
		}
	}
	final, err := inspectMetadata(fd, unix.S_IFDIR, 0)
	if err != nil || final != initial {
		return Observation{}, ErrMismatch
	}
	if ctx.Err() != nil {
		return Observation{}, ctx.Err()
	}
	return Observation{Files: len(p.files), Aliases: len(p.aliases), Bytes: p.bytes}, nil
}

func openBeneath(root int, name string, flags int) (int, error) {
	// openat2 rejects unsupported O_PATH flag combinations. Nonblocking is
	// useful only for data opens, to avoid a replaced FIFO/device blocking.
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NONBLOCK
	}
	fd, err := unix.Openat2(root, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return -1, ErrMismatch
	}
	return fd, nil
}

func inspectMetadata(fd int, kind uint16, mount uint64) (unix.Statx_t, error) {
	var st unix.Statx_t
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &st) != nil || st.Mask&required != required || st.Mnt_id == 0 {
		return st, ErrUnavailable
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil {
		return st, ErrUnavailable
	}
	if !localCodeFilesystem(int64(fs.Type)) || st.Mode&unix.S_IFMT != kind || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 ||
		st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 || fs.Flags&unix.ST_RDONLY == 0 ||
		(mount != 0 && st.Mnt_id != mount) {
		return st, ErrMismatch
	}
	return st, nil
}

func localCodeFilesystem(kind int64) bool {
	// Runtime code must not turn verification into reads from remote/FUSE or
	// other unqualified backing services. This is not ext media qualification.
	switch kind {
	case unix.TMPFS_MAGIC, unix.SQUASHFS_MAGIC, unix.EXT4_SUPER_MAGIC:
		return true
	default:
		return false
	}
}

func (p *Plan) census(ctx context.Context, root int, name string, mount uint64, seen map[string]bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.nodes[name] != 'd' || seen[name] {
		return ErrMismatch
	}
	fd, err := openBeneath(root, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "runtime-census")
	defer directory.Close()
	if _, err := inspectMetadata(fd, unix.S_IFDIR, mount); err != nil {
		return err
	}
	seen[name] = true
	entries, err := directory.ReadDir(len(p.nodes) + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	if len(entries) > len(p.nodes) {
		return ErrMismatch
	}
	for _, entry := range entries {
		child := path.Join(name, entry.Name())
		kind := p.nodes[child]
		if kind == 0 || seen[child] {
			return ErrMismatch
		}
		if kind == 'd' {
			if err := p.census(ctx, root, child, mount, seen); err != nil {
				return err
			}
			continue
		}
		var stat unix.Statx_t
		if unix.Statx(fd, entry.Name(), unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT,
			unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &stat) != nil ||
			stat.Mask&(unix.STATX_TYPE|unix.STATX_MNT_ID_UNIQUE) != (unix.STATX_TYPE|unix.STATX_MNT_ID_UNIQUE) ||
			stat.Mnt_id != mount || stat.Uid != 0 || stat.Gid != 0 {
			return ErrMismatch
		}
		if (kind == 'f' && stat.Mode&unix.S_IFMT != unix.S_IFREG) ||
			(kind == 'l' && stat.Mode&unix.S_IFMT != unix.S_IFLNK) {
			return ErrMismatch
		}
		seen[child] = true
	}
	return nil
}

func inspectFile(ctx context.Context, root int, mount uint64, expected File) error {
	fd, err := openBeneath(root, expected.Path, unix.O_RDONLY)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "runtime-object")
	defer file.Close()
	before, err := inspectMetadata(fd, unix.S_IFREG, mount)
	if err != nil || before.Size != uint64(expected.Size) || uint32(before.Mode&07777) != expected.Mode || before.Nlink != 1 {
		return ErrMismatch
	}
	_, err = unix.Fgetxattr(fd, "security.capability", nil)
	if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return ErrMismatch
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	reader := io.LimitReader(file, expected.Size+1)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count, readErr := reader.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
			total += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ErrUnavailable
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	after, err := inspectMetadata(fd, unix.S_IFREG, mount)
	if err != nil || after != before || total != expected.Size || digest != expected.SHA256 {
		return ErrMismatch
	}
	return nil
}

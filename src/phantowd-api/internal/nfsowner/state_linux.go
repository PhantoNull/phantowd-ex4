// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	_ "embed"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"golang.org/x/sys/unix"
)

//go:embed nfs.conf
var managedNFSConfig string

const (
	nfsConfigPath = "/etc/nfs.conf"
	nfsStateName  = "phantowd-nfs-state"
	nfsStatePath  = "/run/" + nfsStateName
)

type runtimeState struct {
	run, dir  *os.File
	uncertain *os.File
	created   bool
}

type stateConstructionReview struct {
	constructionreview.Marker
	state *runtimeState
	cause error
}

func (*stateConstructionReview) Error() string   { return "NFS state construction requires review" }
func (r *stateConstructionReview) Unwrap() error { return r.cause }

func prepareRuntimeState(ctx context.Context) (_ *runtimeState, result error) {
	if err := verifyNFSConfig(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/run", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	s := &runtimeState{run: os.NewFile(uintptr(fd), "nfs-run-parent")}
	defer func() {
		if result == nil {
			return
		}
		cause, retain := constructionreview.Rollback(result, s.release)
		if retain {
			result = &stateConstructionReview{state: s, cause: cause}
		} else {
			result = cause
		}
	}()
	if err := s.checkRun(); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(fd, nfsStateName, 0700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrState
		}
		return nil, err
	}
	s.created = true
	dir, err := unix.Openat2(fd, nfsStateName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	s.dir = os.NewFile(uintptr(dir), "nfs-private-state")
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	// nfs-utils needs a readable etab for its first export transaction.
	for _, name := range []string{"etab", "rmtab"} {
		table, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(table), name)
		if err := file.Close(); err != nil {
			s.uncertain = file
			return nil, err
		}
	}
	return s, nil
}

func verifyNFSConfig(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// nfs-utils 2.8.6 reads its vendor file and both drop-in directories.
	for _, path := range []string{"/usr/etc/nfs.conf", "/usr/etc/nfs.conf.d", "/etc/nfs.conf.d"} {
		var info unix.Stat_t
		if err := unix.Lstat(path, &info); !errors.Is(err, unix.ENOENT) {
			return ErrState
		}
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, nfsConfigPath, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "nfs-state-config")
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode != unix.S_IFREG|0644 || info.Uid != 0 ||
		info.Gid != 0 || info.Nlink != 1 || info.Size != int64(len(managedNFSConfig)) {
		return errors.Join(ErrState, err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(len(managedNFSConfig)+1)))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	if string(data) != managedNFSConfig {
		return ErrState
	}
	return ctx.Err()
}

func (s *runtimeState) checkRun() error {
	fd := int(s.run.Fd())
	var held, path unix.Statx_t
	const mask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &held) != nil ||
		unix.Statx(unix.AT_FDCWD, "/run", unix.AT_SYMLINK_NOFOLLOW, mask, &path) != nil ||
		held.Mask&mask != mask || path.Mask&mask != mask || held.Ino != path.Ino || held.Mnt_id != path.Mnt_id ||
		held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Mode&0022 != 0 || held.Uid != 0 || held.Gid != 0 ||
		path.Mode != held.Mode || path.Uid != 0 || path.Gid != 0 {
		return ErrState
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrState
	}
	return nil
}

func (s *runtimeState) checkDirectory() error {
	if s.dir == nil {
		return ErrState
	}
	if err := s.checkRun(); err != nil {
		return err
	}
	var held, path unix.Statx_t
	const mask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(int(s.dir.Fd()), "", unix.AT_EMPTY_PATH, mask, &held) != nil ||
		unix.Statx(int(s.run.Fd()), nfsStateName, unix.AT_SYMLINK_NOFOLLOW, mask, &path) != nil ||
		held.Mask&mask != mask || path.Mask&mask != mask || held.Ino != path.Ino || held.Mnt_id != path.Mnt_id ||
		held.Mode != unix.S_IFDIR|0700 || path.Mode != held.Mode || held.Uid != 0 || held.Gid != 0 ||
		path.Uid != 0 || path.Gid != 0 {
		return ErrState
	}
	return nil
}

func (s *runtimeState) check(ctx context.Context) error {
	if err := s.checkDirectory(); err != nil {
		return err
	}
	return verifyNFSConfig(ctx)
}

// release runs with no service child and deletes only the original nfs-utils
// state. An unexpected entry retains the directory for review.
func (s *runtimeState) release() error {
	if s.uncertain != nil {
		return ErrState
	}
	if s.created {
		if err := s.checkDirectory(); err != nil {
			return err
		}
		fd := int(s.dir.Fd())
		names, err := s.dir.Readdirnames(5)
		if err != nil && !errors.Is(err, io.EOF) || len(names) > 4 {
			return ErrState
		}
		for _, name := range names {
			switch name {
			case "etab", ".etab.lock", "rmtab", ".rmtab.lock":
			default:
				return ErrState
			}
			var info unix.Stat_t
			if unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
				info.Uid != 0 || info.Gid != 0 || info.Nlink != 1 {
				return ErrState
			}
		}
		for _, name := range names {
			if err := unix.Unlinkat(fd, name, 0); err != nil {
				return err
			}
		}
		if err := s.checkDirectory(); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(s.run.Fd()), nfsStateName, unix.AT_REMOVEDIR); err != nil {
			return err
		}
		if err := s.dir.Close(); err != nil {
			return err
		}
	}
	return s.run.Close()
}

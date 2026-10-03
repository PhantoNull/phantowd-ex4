// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"context"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const currentName = "volumes.json"

// Reader owns a separate descriptor/shared flock, not the caller's descriptor.
// Its effective owner UID is bound at construction. All eventual writers must
// honor the same directory flock. Trusted parent/provisioning is a prerequisite.
// No constructor accepts a path, owner UID or filename from a request.
type Reader struct {
	mu     sync.Mutex
	dir    int
	uid    uint32
	ready  bool
	closed bool
}

func Open(directory *os.File) (*Reader, error) {
	if directory == nil {
		return nil, ErrObservation
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, ErrObservation
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat2(int(parent), ".", &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	})
	if err != nil || openErr != nil || fd < 0 {
		if fd >= 0 {
			unix.Close(fd)
		}
		return nil, ErrObservation
	}
	r := &Reader{dir: fd, uid: uint32(os.Geteuid())}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !r.privateDirectory(st) || unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return nil, ErrObservation
	}
	r.ready = true
	return r, nil
}

func (r *Reader) privateDirectory(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == r.uid
}

func (r *Reader) privateFile(st unix.Stat_t, directory unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == r.uid &&
		st.Nlink == 1 && st.Size > 0 && st.Size <= MaxInputBytes && st.Dev == directory.Dev
}

// Ignore access time only. No content or identity metadata may change while
// observing; O_NOATIME below prevents reads from requesting an atime update.
func sameMetadata(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (r *Reader) Read(ctx context.Context) (Snapshot, error) {
	return r.read(ctx, nil)
}

// afterRead is a package-private deterministic syscall-race test seam. The
// real reader always supplies nil; no runtime/request-configurable backend.
func (r *Reader) read(ctx context.Context, afterRead func()) (Snapshot, error) {
	if r == nil {
		return Snapshot{}, ErrObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready || r.closed || ctx == nil || ctx.Err() != nil {
		return Snapshot{}, ErrObservation
	}
	var directory, before unix.Stat_t
	if unix.Fstat(r.dir, &directory) != nil || !r.privateDirectory(directory) ||
		unix.Fstatat(r.dir, currentName, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !r.privateFile(before, directory) {
		return Snapshot{}, ErrObservation
	}
	fd, err := unix.Openat2(r.dir, currentName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOATIME,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return Snapshot{}, ErrObservation
	}
	f := os.NewFile(uintptr(fd), currentName)
	defer f.Close()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || !r.privateFile(opened, directory) || !sameMetadata(before, opened) {
		return Snapshot{}, ErrObservation
	}
	d, err := Decode(f)
	if afterRead != nil {
		afterRead()
	}
	var after, named, currentDirectory unix.Stat_t
	if err != nil || ctx.Err() != nil || unix.Fstat(fd, &after) != nil ||
		unix.Fstatat(r.dir, currentName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		unix.Fstat(r.dir, &currentDirectory) != nil || !sameMetadata(opened, after) ||
		!sameMetadata(after, named) || !sameMetadata(directory, currentDirectory) {
		return Snapshot{}, ErrObservation
	}
	if f.Close() != nil {
		return Snapshot{}, ErrObservation
	}
	return Snapshot{document: d, observed: true}, nil
}

func (r *Reader) Close() error {
	if r == nil {
		return ErrObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready || r.closed {
		return ErrObservation
	}
	r.closed = true
	if unix.Close(r.dir) != nil {
		return ErrObservation
	}
	return nil
}

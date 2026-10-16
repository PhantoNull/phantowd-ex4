//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type directoryAnchor struct {
	parent            *os.File
	name              string
	parentID, childID unix.Stat_t
}

const anchoredResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// Each cursor is a new open-file description: enumeration never consumes the
// Store's directory offset. Read at most two names to prove a complete census
// containing only the optional current document.
func anchoredCensus(fd int, current string) bool {
	cursorFD, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOATIME | unix.O_CLOEXEC, Resolve: anchoredResolve})
	if err != nil {
		return false
	}
	cursor := os.NewFile(uintptr(cursorFD), "anchored-store-census")
	names, readErr := cursor.Readdirnames(2)
	complete := errors.Is(readErr, io.EOF)
	if !complete && readErr == nil && len(names) < 2 {
		more, e := cursor.Readdirnames(1)
		names = append(names, more...)
		complete = errors.Is(e, io.EOF) && len(more) == 0
	}
	closeErr := cursor.Close()
	return closeErr == nil && complete && (len(names) == 0 || len(names) == 1 && names[0] == current)
}

func sameDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode&unix.S_IFMT == unix.S_IFDIR && a.Mode&07777 == 0700 && a.Uid == uint32(os.Geteuid())
}
func (a *directoryAnchor) matches(child int) bool {
	var parent, held, named unix.Stat_t
	if a == nil || a.parent == nil || unix.Fstat(int(a.parent.Fd()), &parent) != nil || !sameDirectory(parent, a.parentID) || unix.Fstat(child, &held) != nil || !sameDirectory(held, a.childID) {
		return false
	}
	fd, err := unix.Openat2(int(a.parent.Fd()), a.name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_CLOEXEC, Resolve: anchoredResolve})
	if err != nil {
		return false
	}
	statErr := unix.Fstat(fd, &named)
	closeErr := unix.Close(fd)
	return statErr == nil && closeErr == nil && sameDirectory(named, a.childID)
}

// OpenAnchoredWithCodec captures a fixed child of a trusted, borrowed original
// parent. It owns the NEW child's actual flock/FD; no caller FD is adopted or
// duplicated. Parent ownership, stable trusted ancestors and suitable local
// filesystem remain caller prerequisites. Caller closes the parent only AFTER
// all child Stores, never concurrently with their operations. No fsync,
// initialization, pending cleanup or recovery occurs.
// Every attempted mutation error poisons this strict instance; legacy Open is
// unchanged. A successful open does NOT establish historical confirmation.
func OpenAnchoredWithCodec[T any](parent *os.File, name string, codec Codec[T]) (*Store[T], error) {
	if parent == nil || !codec.valid() || name == "" || name == "." || name == ".." || len(name) > 64 || filepath.Base(name) != name {
		return nil, ErrUnsafe
	}
	a := &directoryAnchor{parent: parent, name: name}
	if unix.Fstat(int(parent.Fd()), &a.parentID) != nil || !sameDirectory(a.parentID, a.parentID) {
		return nil, ErrUnsafe
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_CLOEXEC, Resolve: anchoredResolve})
	if err != nil {
		return nil, ErrUnsafe
	}
	s := &Store[T]{dir: fd, ready: true, codec: codec, io: systemOps(), noAtime: true, anchored: a}
	if unix.Fstat(fd, &a.childID) != nil || !sameDirectory(a.childID, a.childID) || a.childID.Dev != a.parentID.Dev {
		s.Close()
		return nil, ErrUnsafe
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		s.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrIO
	}
	if !anchoredCensus(fd, codec.CurrentName) {
		s.Close()
		return nil, ErrReview
	}
	if _, _, err := s.loadExact(); err != nil && !errors.Is(err, ErrNotInitialized) {
		s.Close()
		return nil, err
	}
	if !a.matches(fd) || !anchoredCensus(fd, codec.CurrentName) {
		s.Close()
		return nil, ErrReview
	}
	return s, nil
}

// LoadExact returns defensive data from ONE original bounded file read under
// the same Store lock. Bytes/value are observations, never confirmation or a
// lease. No sync is performed; every failure returns no partial data/value.
func (s *Store[T]) LoadExact() (T, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero T
	if err := s.check(); err != nil {
		return zero, nil, err
	}
	v, data, err := s.loadExact()
	if err != nil && s.anchored != nil && !errors.Is(err, ErrNotInitialized) {
		s.uncertain = true
	}
	if s.anchored != nil && (err == nil || errors.Is(err, ErrNotInitialized)) && s.check() != nil {
		clear(data)
		s.uncertain = true
		return zero, nil, ErrUncertain
	}
	return v, data, err
}
func (s *Store[T]) loadExact() (T, []byte, error) {
	var zero T
	f, err := s.openCurrent()
	if err != nil {
		return zero, nil, err
	}
	var before, after, named unix.Stat_t
	statBefore := unix.Fstat(int(f.Fd()), &before)
	data, readErr := io.ReadAll(io.LimitReader(f, int64(s.codec.MaxBytes)+1))
	statAfter := unix.Fstat(int(f.Fd()), &after)
	namedErr := unix.Fstatat(s.dir, s.codec.CurrentName, &named, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
	closeErr := f.Close()
	if statBefore != nil || statAfter != nil || namedErr != nil || closeErr != nil || readErr != nil || len(data) > s.codec.MaxBytes || policyStamp(before) != policyStamp(after) || policyStamp(after) != policyStamp(named) {
		clear(data)
		return zero, nil, ErrIO
	}
	v, err := s.codec.Decode(bytes.NewReader(data))
	if err != nil || s.codec.Validate(v) != nil {
		clear(data)
		return zero, nil, ErrInvalid
	}
	return v, data, nil
}

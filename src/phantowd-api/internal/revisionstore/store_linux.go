// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package revisionstore provides single-document desired-policy transactions.
// Its Linux backend requires a private, pre-provisioned local directory.
package revisionstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	ErrNotInitialized = errors.New("share configuration is not initialized")
	ErrConflict       = errors.New("share configuration revision conflict")
	ErrInvalid        = errors.New("invalid share configuration")
	ErrUnsafe         = errors.New("unsafe share configuration storage")
	ErrBusy           = errors.New("share configuration storage is locked")
	ErrIO             = errors.New("share configuration storage I/O failure")
	ErrUncertain      = errors.New("share configuration durability uncertain; close and reopen storage")
	ErrClosed         = errors.New("share configuration storage is closed")
)

// Codec is trusted in-process schema code, not an HTTP-supplied option. Decode
// must enforce the full schema and its size limit; Revision must be pure.
type Codec[T any] struct {
	CurrentName string
	PendingName string
	MaxBytes    int
	Decode      func(io.Reader) (T, error)
	Validate    func(T) error
	Revision    func(T) uint64
}

// Store holds an exclusive advisory directory lock until Close. All writers
// must use this store, and no other code may modify/replace its directory.
// It is safe for concurrent method calls, but callers must not concurrently
// mutate a Config passed to Commit. It must not be copied after construction.
type Store[T any] struct {
	mu        sync.Mutex
	dir       int
	ready     bool
	closed    bool
	uncertain bool
	io        fileOps
	codec     Codec[T]
}

// These unexported operations allow deterministic syscall-failure tests.
type fileOps struct {
	write   func(*os.File, []byte) (int, error)
	sync    func(*os.File) error
	close   func(*os.File) error
	rename  func(int, string, int, string) error
	syncDir func(int) error
}

func systemOps() fileOps {
	return fileOps{(*os.File).Write, (*os.File).Sync, (*os.File).Close, unix.Renameat, unix.Fsync}
}

// Open does not create the directory or initialize/reset configuration. The
// caller must provision a 0700 directory owned by the effective UID under
// trusted parents on a local filesystem with flock, rename and fsync support.
// No symlink is accepted as the final directory component. Descendant access
// uses fixed names relative to the retained directory descriptor.
func OpenWithCodec[T any](directory string, codec Codec[T]) (*Store[T], error) {
	// Bound the trusted adapter too; no path traversal or unbounded file reads.
	validName := func(name string) bool {
		return len(name) > 0 && len(name) <= 64 && name != "." && name != ".." && filepath.Base(name) == name
	}
	if !validName(codec.CurrentName) || !validName(codec.PendingName) || codec.CurrentName == codec.PendingName ||
		codec.MaxBytes <= 0 || codec.MaxBytes > 1<<20 || codec.Decode == nil || codec.Validate == nil || codec.Revision == nil {
		return nil, ErrUnsafe
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrUnsafe
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	s := &Store[T]{dir: fd, ready: true, io: systemOps(), codec: codec}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, ErrUnsafe
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrIO
	}
	// Refuse corruption; never select a staged document or silently reset it.
	if _, err := s.load(); err != nil && !errors.Is(err, ErrNotInitialized) {
		s.Close()
		return nil, err
	}
	// Re-establish a successful sync boundary when reopening after uncertainty.
	// A valid file alone cannot establish the outcome of a failed directory sync.
	if err := s.syncCurrent(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store[T]) check() error {
	if !s.ready || s.closed {
		return ErrClosed
	}
	if s.uncertain {
		return ErrUncertain
	}
	return nil
}

func (s *Store[T]) openCurrent() (*os.File, error) {
	currentName := s.codec.CurrentName
	var before unix.Stat_t
	err := unix.Fstatat(s.dir, currentName, &before, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrNotInitialized
	}
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, ErrUnsafe
	}
	fd, err := unix.Openat(s.dir, currentName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, ErrUnsafe
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size > int64(s.codec.MaxBytes) ||
		st.Dev != before.Dev || st.Ino != before.Ino {
		unix.Close(fd)
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(fd), currentName), nil
}

func (s *Store[T]) syncCurrent() error {
	f, err := s.openCurrent()
	if err != nil && !errors.Is(err, ErrNotInitialized) {
		return err
	}
	if f != nil {
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil {
			return ErrIO
		}
	}
	if unix.Fsync(s.dir) != nil {
		return ErrIO
	}
	return nil
}

func (s *Store[T]) load() (T, error) {
	var zero T
	f, err := s.openCurrent()
	if err != nil {
		return zero, err
	}
	c, decodeErr := s.codec.Decode(f)
	closeErr := f.Close()
	if decodeErr != nil {
		return zero, ErrInvalid
	}
	if closeErr != nil {
		return zero, ErrIO
	}
	return c, nil
}

// Load returns a newly decoded snapshot. Missing state is distinct from empty
// configured state, corruption and an uncertain previous commit.
func (s *Store[T]) Load() (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		var zero T
		return zero, err
	}
	return s.load()
}

// Commit requires next.Revision == expected+1. expected=0 is initialization,
// allowed only when no current file exists. Success means file sync, rename
// and directory sync all succeeded. It does not mean any NAS service changed.
// On ErrUncertain publication was attempted but durability was not confirmed: do
// not retry or activate services; close, reopen and reconcile the loaded state.
func (s *Store[T]) Commit(expected uint64, next T) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return err
	}
	if expected == math.MaxUint64 || s.codec.Revision(next) != expected+1 {
		return ErrConflict
	}
	// Bound constructed input before JSON allocation, then independently check
	// the encoded/decoded persistence contract below.
	if s.codec.Validate(next) != nil {
		return ErrInvalid
	}
	data, err := json.Marshal(next)
	if err != nil || len(data) > s.codec.MaxBytes {
		return ErrInvalid
	}
	// Match the exact persistence decoding contract, including encoded size.
	if _, err := s.codec.Decode(bytes.NewReader(data)); err != nil {
		return ErrInvalid
	}
	current, err := s.load()
	if err != nil && !errors.Is(err, ErrNotInitialized) {
		return err
	}
	currentRevision := uint64(0)
	if err == nil {
		currentRevision = s.codec.Revision(current)
	}
	if currentRevision != expected {
		return ErrConflict
	}
	// Only the single reserved pending file is disposable. It is never a
	// recovery candidate; refusal of suspicious entries preserves evidence.
	currentName, pendingName := s.codec.CurrentName, s.codec.PendingName
	var st unix.Stat_t
	err = unix.Fstatat(s.dir, pendingName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 ||
			st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
			return ErrUnsafe
		}
		if unix.Unlinkat(s.dir, pendingName, 0) != nil {
			return ErrIO
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return ErrIO
	}
	fd, err := unix.Openat(s.dir, pendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrIO
	}
	f := os.NewFile(uintptr(fd), pendingName)
	n, writeErr := s.io.write(f, data)
	var syncErr error
	if writeErr == nil && n == len(data) {
		syncErr = s.io.sync(f)
	}
	closeErr := s.io.close(f)
	// Keep the bounded pending entry on failure for the next commit to discard.
	if writeErr != nil || n != len(data) || syncErr != nil || closeErr != nil {
		return ErrIO
	}
	if s.io.rename(s.dir, pendingName, s.dir, currentName) != nil {
		s.uncertain = true
		return ErrUncertain
	}
	if s.io.syncDir(s.dir) != nil {
		s.uncertain = true
		return ErrUncertain
	}
	return nil
}

// Close releases the directory and its lock. It is idempotent.
func (s *Store[T]) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || s.closed {
		return nil
	}
	s.closed = true
	if unix.Close(s.dir) != nil {
		return ErrIO
	}
	return nil
}

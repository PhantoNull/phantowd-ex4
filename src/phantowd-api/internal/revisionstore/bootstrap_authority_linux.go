//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// BootstrapAuthority retains one read-only directory/codec/watch/lock lifetime.
// It cannot initialize, publish, recover, issue leases or admit an Owner. Its
// observations are values, not durability/provenance/admission permissions.
// Parents/provisioning/cooperating writers remain trusted prerequisites.
type BootstrapAuthority[T any] struct {
	mu                          sync.Mutex
	self                        *BootstrapAuthority[T]
	root                        *os.File
	initial                     unix.Stat_t
	codec                       Codec[T]
	watch                       int
	review, closed, closeFailed bool
}

func OpenBootstrapAuthorityWithCodec[T any](ctx context.Context, directory string, codec Codec[T]) (authority *BootstrapAuthority[T], result error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if !codec.valid() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := &BootstrapAuthority[T]{codec: codec, watch: -1}
	a.self = a
	defer func() {
		if result != nil {
			if err := a.Close(); err != nil {
				a.review = true
				authority = a // Keep unattempted originals reachable on uncertain cleanup.
				result = errors.Join(ErrReview, result, err)
			}
		}
	}()
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrIO
	}
	a.root = os.NewFile(uintptr(fd), "bootstrap-authority-original-directory")
	if unix.Fstat(fd, &a.initial) != nil || a.initial.Mode&unix.S_IFMT != unix.S_IFDIR || a.initial.Mode&07777 != 0700 || a.initial.Uid != uint32(os.Geteuid()) {
		return nil, ErrUnsafe
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrIO
	}
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrIO
	}
	a.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, ErrIO
	}
	if wd, err := unix.InotifyAddWatch(a.watch, "/proc/self/fd/"+strconv.Itoa(fd), policyEvents|unix.IN_ONLYDIR); err != nil || wd < 0 {
		return nil, ErrIO
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || policyStamp(after) != policyStamp(a.initial) || !a.quietLocked() {
		return nil, ErrReview
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *BootstrapAuthority[T]) valid() bool { return a != nil && a.self == a }

func (a *BootstrapAuthority[T]) quietLocked() bool {
	if a.watch < 0 {
		return false
	}
	var buffer [4096]byte
	n, err := unix.Read(a.watch, buffer[:])
	return n == -1 && errors.Is(err, unix.EAGAIN)
}

// Observe serializes fresh reads under the SAME original lock/watch. A separate
// confined cursor avoids sharing buffered directory positions between calls;
// it never acquires/replaces the authority's root, lock, codec or watch.
func (a *BootstrapAuthority[T]) Observe(ctx context.Context) (BootstrapObservation, error) {
	if !a.valid() || ctx == nil {
		return BootstrapObservation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return BootstrapObservation{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closeFailed {
		return BootstrapObservation{}, ErrReview
	}
	if a.closed {
		return BootstrapObservation{}, ErrClosed
	}
	if a.review {
		return BootstrapObservation{}, ErrReview
	}
	if err := ctx.Err(); err != nil {
		return BootstrapObservation{}, err
	}
	fail := func(cause error) (BootstrapObservation, error) {
		a.review = true
		return BootstrapObservation{}, errors.Join(ErrReview, cause)
	}
	var rootStat unix.Stat_t
	if a.root == nil || unix.Fstat(int(a.root.Fd()), &rootStat) != nil || policyStamp(rootStat) != policyStamp(a.initial) || !a.quietLocked() {
		return fail(ErrReview)
	}
	fd, err := unix.Openat2(int(a.root.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOATIME | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fail(ErrIO)
	}
	cursor := os.NewFile(uintptr(fd), "bootstrap-authority-confined-read-cursor")
	var cursorStat unix.Stat_t
	if unix.Fstat(fd, &cursorStat) != nil || policyStamp(cursorStat) != policyStamp(a.initial) {
		return fail(errors.Join(ErrReview, cursor.Close()))
	}
	observed, readErr := observeBootstrapHeld(ctx, cursor, a.codec, a.initial, a.quietLocked)
	closeErr := cursor.Close()
	if readErr != nil || closeErr != nil {
		return fail(errors.Join(readErr, closeErr))
	}
	if unix.Fstat(int(a.root.Fd()), &rootStat) != nil || policyStamp(rootStat) != policyStamp(a.initial) || !a.quietLocked() {
		return fail(ErrReview)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return observed, nil
}

// No consumer/lease is issued by this type. Explicit Close releases only this
// observer lifetime, never reconciles state or clears review for a future boot.
// Close errors are terminal: retain unattempted originals, never retry a raw FD.
func (a *BootstrapAuthority[T]) Close() error {
	if !a.valid() {
		return ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closeFailed {
		return ErrReview
	}
	if a.closed {
		return nil
	}
	if a.watch >= 0 {
		if unix.Close(a.watch) != nil {
			a.review, a.closeFailed = true, true
			return ErrReview
		}
		a.watch = -1
	}
	if a.root != nil {
		if a.root.Close() != nil {
			a.review, a.closeFailed = true, true
			return ErrReview
		}
	}
	a.closed = true
	return nil
}

func (*BootstrapAuthority[T]) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*BootstrapAuthority[T]) UnmarshalJSON([]byte) error   { return ErrInvalid }

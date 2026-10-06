//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrReview = errors.New("desired policy requires review; no automatic retry")

const maxPolicyLeases = 256
const policyEvents = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_UNMOUNT | unix.IN_IGNORED | unix.IN_Q_OVERFLOW

// OwnedStore is the sole writer and lifetime owner of an initialized desired
// document. It keeps the Store's directory flock and refuses publication/Close
// while any private lease remains. It neither launches nor stops consumers.
// The caller must keep a lease until independently confirmed consumer teardown.
// Trusted, exclusive directory provisioning and cooperating writers are required.
// A copied value is invalid. Lock order is OwnedStore.mu then Store.mu.
type OwnedStore[T any] struct {
	mu          sync.Mutex
	self        *OwnedStore[T]
	store       *Store[T]
	watch       int
	baseline    policyObservation
	leases      map[*PolicyLease[T]]struct{}
	review      bool
	closed      bool
	closeFailed bool
}

// PolicyLease is a private, constructor-issued claim on one desired revision,
// not mount, identity, credential, writable-backing or execution authority.
// Snapshots are defensive values; their revision is not itself a capability.
// Release removes only this claim, never a process/session or filesystem use.
type PolicyLease[T any] struct {
	self     *PolicyLease[T]
	owner    *OwnedStore[T]
	revision uint64
	released bool // guarded by owner.mu
}

type policyMetadata struct {
	device, inode, links uint64
	mode, uid, gid       uint32
	size                 int64
	modified, mNanos     int64
	changed, cNanos      int64
}

type policyObservation struct {
	directory, file policyMetadata
	digest          [32]byte
	revision        uint64
}

func policyStamp(st unix.Stat_t) policyMetadata {
	return policyMetadata{uint64(st.Dev), uint64(st.Ino), uint64(st.Nlink), st.Mode, st.Uid, st.Gid,
		st.Size, int64(st.Mtim.Sec), int64(st.Mtim.Nsec), int64(st.Ctim.Sec), int64(st.Ctim.Nsec)}
}

// OpenOwnedWithCodec requires valid initialized state. It reuses the existing
// transaction engine; it never initializes, imports, resets or promotes pending
// state. No background poller, recovery or HTTP boundary is installed here.
func OpenOwnedWithCodec[T any](directory string, codec Codec[T]) (*OwnedStore[T], error) {
	s, err := OpenWithCodec(directory, codec)
	if err != nil {
		return nil, err
	}
	s.noAtime = true
	o := &OwnedStore[T]{store: s, watch: -1, leases: make(map[*PolicyLease[T]]struct{})}
	o.self = o
	if err := o.newEpochLocked(); err != nil {
		if o.Close() != nil {
			return nil, ErrReview
		}
		return nil, err
	}
	return o, nil
}

func (o *OwnedStore[T]) valid() bool { return o != nil && o.self == o && o.store != nil }

func (o *OwnedStore[T]) checkLocked(ctx context.Context) error {
	if o.review || o.closeFailed {
		return ErrReview
	}
	if o.closed {
		return ErrClosed
	}
	if ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}

func (o *OwnedStore[T]) quarantineLocked() error {
	o.review = true
	return ErrReview
}

// An epoch has no permitted external directory mutations. Any queued event,
// including overflow/watch loss or malformed/unknown data, quarantines it.
// One bounded nonblocking read is sufficient: only an empty queue is healthy.
// Event names/cookies never become selectors, logs or output.
func (o *OwnedStore[T]) quietLocked() bool {
	if o.watch < 0 {
		return false
	}
	var buffer [4096]byte
	n, err := unix.Read(o.watch, buffer[:])
	return n == -1 && errors.Is(err, unix.EAGAIN)
}

func (o *OwnedStore[T]) newEpochLocked() error {
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return o.quarantineLocked()
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return o.quarantineLocked()
	}
	if wd, err := unix.InotifyAddWatch(fd, "/proc/self/fd/"+strconv.Itoa(o.store.dir), policyEvents|unix.IN_ONLYDIR); err != nil || wd < 0 {
		unix.Close(fd)
		return o.quarantineLocked()
	}
	old := o.watch
	o.watch = fd
	if old >= 0 && unix.Close(old) != nil {
		return o.quarantineLocked()
	}
	_, observed, err := o.captureLocked()
	if err != nil {
		return err
	}
	o.baseline = observed
	return nil
}

// Bracket the actual fixed-name file read with metadata and mutation checks.
// Unlike a cached value, this detects replacement and restored-content ABA.
// Access time is ignored; owned reads use O_NOATIME and never request updates.
func (o *OwnedStore[T]) captureLocked() (T, policyObservation, error) {
	var zero T
	s := o.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !o.quietLocked() || s.check() != nil {
		return zero, policyObservation{}, o.quarantineLocked()
	}
	var dir, named unix.Stat_t
	if unix.Fstat(s.dir, &dir) != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR || dir.Mode&07777 != 0700 || dir.Uid != uint32(os.Geteuid()) {
		return zero, policyObservation{}, o.quarantineLocked()
	}
	f, err := s.openCurrent()
	if err != nil {
		// Only construction reports missing state directly; live loss is review.
		if errors.Is(err, ErrNotInitialized) && o.baseline.revision == 0 {
			return zero, policyObservation{}, ErrNotInitialized
		}
		return zero, policyObservation{}, o.quarantineLocked()
	}
	var before, after, dirAfter unix.Stat_t
	fd := int(f.Fd())
	if unix.Fstat(fd, &before) != nil || before.Dev != dir.Dev {
		f.Close()
		return zero, policyObservation{}, o.quarantineLocked()
	}
	doc, decodeErr := s.codec.Decode(f)
	metadataOK := unix.Fstat(fd, &after) == nil && unix.Fstatat(s.dir, s.codec.CurrentName, &named, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(s.dir, &dirAfter) == nil && policyStamp(before) == policyStamp(after) &&
		policyStamp(after) == policyStamp(named) && policyStamp(dir) == policyStamp(dirAfter)
	closeErr := f.Close()
	if decodeErr != nil || !metadataOK || closeErr != nil || !o.quietLocked() || s.codec.Validate(doc) != nil || s.codec.Revision(doc) == 0 {
		return zero, policyObservation{}, o.quarantineLocked()
	}
	encoded, err := json.Marshal(doc)
	if err != nil || len(encoded) > s.codec.MaxBytes {
		return zero, policyObservation{}, o.quarantineLocked()
	}
	return doc, policyObservation{policyStamp(dirAfter), policyStamp(after), sha256.Sum256(encoded), s.codec.Revision(doc)}, nil
}

func (o *OwnedStore[T]) observeLocked() (T, error) {
	doc, observed, err := o.captureLocked()
	if err != nil || observed != o.baseline {
		var zero T
		return zero, o.quarantineLocked()
	}
	return doc, nil
}

// Snapshot is a fresh read-only value, not a lease or activation permission.
func (o *OwnedStore[T]) Snapshot(ctx context.Context) (T, error) {
	var zero T
	if !o.valid() {
		return zero, ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkLocked(ctx); err != nil {
		return zero, err
	}
	doc, err := o.observeLocked()
	if err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return doc, nil
}

func (o *OwnedStore[T]) Acquire(ctx context.Context, expected uint64) (*PolicyLease[T], error) {
	if !o.valid() {
		return nil, ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkLocked(ctx); err != nil {
		return nil, err
	}
	if _, err := o.observeLocked(); err != nil {
		return nil, err
	}
	if expected != o.baseline.revision {
		return nil, ErrConflict
	}
	if len(o.leases) >= maxPolicyLeases {
		return nil, ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l := &PolicyLease[T]{owner: o, revision: expected}
	l.self = l
	o.leases[l] = struct{}{}
	return l, nil
}

// Commit refuses active claims and reuses the existing fsync/rename transaction.
// Any attempted publication failure quarantines the owner without retry; an
// explicit successful commit with no old leases establishes a new watch epoch.
// The next value remains caller-owned and must not be concurrently mutated.
func (o *OwnedStore[T]) Commit(ctx context.Context, expected uint64, next T) error {
	if !o.valid() {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkLocked(ctx); err != nil {
		return err
	}
	if _, err := o.observeLocked(); err != nil {
		return err
	}
	if len(o.leases) != 0 {
		return ErrBusy
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := o.store.Commit(expected, next); err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalid) {
			return err
		}
		return o.quarantineLocked()
	}
	if err := o.newEpochLocked(); err != nil {
		return o.quarantineLocked()
	}
	encoded, err := json.Marshal(next)
	if err != nil || o.baseline.revision != o.store.codec.Revision(next) || o.baseline.digest != sha256.Sum256(encoded) {
		return o.quarantineLocked()
	}
	// Cancellation after publication is not a claim that nothing changed.
	if ctx.Err() != nil {
		return o.quarantineLocked()
	}
	return nil
}

func (l *PolicyLease[T]) valid() bool { return l != nil && l.self == l && l.owner.valid() }

func (l *PolicyLease[T]) Snapshot(ctx context.Context) (T, error) {
	var zero T
	if !l.valid() {
		return zero, ErrInvalid
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.leases[l]; !ok || l.released {
		return zero, ErrClosed
	}
	if err := o.checkLocked(ctx); err != nil {
		return zero, err
	}
	doc, err := o.observeLocked()
	if err != nil || l.revision != o.baseline.revision {
		return zero, o.quarantineLocked()
	}
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	return doc, nil
}

func (l *PolicyLease[T]) Verify(ctx context.Context) error {
	_, err := l.Snapshot(ctx)
	return err
}

// Release is an explicit claim release only. A caller with a live or uncertain
// consumer must not release it. Review remains sticky even after all releases.
func (l *PolicyLease[T]) Release() error {
	if !l.valid() {
		return ErrInvalid
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.released {
		return nil
	}
	if _, ok := o.leases[l]; !ok {
		return ErrInvalid
	}
	delete(o.leases, l)
	l.released = true
	return nil
}

// Close cannot release the flock under a live policy claim, including review.
// A failed close is never retried; no descriptor number can be reused blindly.
func (o *OwnedStore[T]) Close() error {
	if !o.valid() {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closeFailed {
		return ErrReview
	}
	if o.closed {
		return nil
	}
	if len(o.leases) != 0 {
		return ErrBusy
	}
	o.closed = true
	var watchErr error
	if o.watch >= 0 {
		watchErr = unix.Close(o.watch)
		o.watch = -1
	}
	storeErr := o.store.Close()
	if watchErr != nil || storeErr != nil {
		o.closeFailed = true
		return o.quarantineLocked()
	}
	return nil
}

func (*OwnedStore[T]) MarshalJSON() ([]byte, error)  { return nil, ErrInvalid }
func (*OwnedStore[T]) UnmarshalJSON([]byte) error    { return ErrInvalid }
func (*PolicyLease[T]) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*PolicyLease[T]) UnmarshalJSON([]byte) error   { return ErrInvalid }

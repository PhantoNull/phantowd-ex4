//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

type BootstrapKind string

const (
	BootstrapEmptyDirectory      BootstrapKind = "empty-directory"
	BootstrapPendingEvidence     BootstrapKind = "pending-evidence"
	BootstrapValidCurrentPolicy  BootstrapKind = "valid-current-policy"
	BootstrapInvalidPolicy       BootstrapKind = "invalid-or-unsupported-policy"
	BootstrapUnrecognizedEntries BootstrapKind = "unrecognized-entries"
)

// BootstrapObservation is a redacted point-in-time value, not a lease,
// enrollment permission or evidence that the whole appliance is pristine.
// A valid current document is not proof of its origin, an acknowledged commit
// or filesystem durability; this observer deliberately performs no fsync.
type BootstrapObservation struct {
	Kind     BootstrapKind
	Revision uint64
}

// ObserveBootstrapWithCodec never syncs, initializes, promotes, deletes or
// publishes state. The codec is trusted in-process code, never caller/HTTP
// supplied. It temporarily takes the existing exclusive directory flock;
// trusted parents/cooperating writers remain prerequisites. No observer result
// may be used as permission for a later operation without retained authority.
func ObserveBootstrapWithCodec[T any](ctx context.Context, directory string, codec Codec[T]) (observation BootstrapObservation, result error) {
	if ctx == nil {
		return BootstrapObservation{}, ErrInvalid
	}
	if !codec.valid() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return BootstrapObservation{}, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return BootstrapObservation{}, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
	if err != nil {
		return BootstrapObservation{}, ErrIO
	}
	root := os.NewFile(uintptr(fd), "bootstrap-original-directory")
	defer func() {
		if root.Close() != nil {
			observation = BootstrapObservation{}
			result = errors.Join(result, ErrIO)
		}
	}()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Mode&07777 != 0700 || before.Uid != uint32(os.Geteuid()) {
		return BootstrapObservation{}, ErrUnsafe
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return BootstrapObservation{}, ErrBusy
		}
		return BootstrapObservation{}, ErrIO
	}
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return BootstrapObservation{}, ErrIO
	}
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return BootstrapObservation{}, ErrIO
	}
	defer func() {
		if unix.Close(watch) != nil {
			observation = BootstrapObservation{}
			result = errors.Join(result, ErrIO)
		}
	}()
	if wd, err := unix.InotifyAddWatch(watch, "/proc/self/fd/"+strconv.Itoa(fd), policyEvents|unix.IN_ONLYDIR); err != nil || wd < 0 {
		return BootstrapObservation{}, ErrIO
	}
	quiet := func() bool {
		var buffer [4096]byte
		n, err := unix.Read(watch, buffer[:])
		return n == -1 && errors.Is(err, unix.EAGAIN)
	}
	return observeBootstrapHeld(ctx, root, codec, before, quiet)
}

// Private shared collector. Caller retains the exclusive original directory
// lock/watch and supplies a read cursor on that same directory. No ownership
// transfer, new backend selector or admission token is exposed.
func observeBootstrapHeld[T any](ctx context.Context, root *os.File, codec Codec[T], before unix.Stat_t, quiet func() bool) (BootstrapObservation, error) {
	fd := int(root.Fd())
	if !quiet() {
		return BootstrapObservation{}, ErrReview
	}
	var names []string
	complete := false
	for len(names) < 3 {
		if err := ctx.Err(); err != nil {
			return BootstrapObservation{}, err
		}
		chunk, readErr := root.Readdirnames(3 - len(names))
		names = append(names, chunk...)
		if errors.Is(readErr, io.EOF) {
			complete = true
			break
		}
		if readErr != nil || len(chunk) == 0 {
			return BootstrapObservation{}, ErrIO
		}
	}
	unrecognized := len(names) > 2 || !complete
	for _, name := range names {
		if name != codec.CurrentName && name != codec.PendingName {
			unrecognized = true
		}
	}
	known := map[string]unix.Stat_t{}
	for _, name := range names {
		if unrecognized {
			break
		} // Observed unknown evidence, never complete/usable state.
		if _, duplicate := known[name]; duplicate {
			return BootstrapObservation{}, ErrReview
		}
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Dev != before.Dev || st.Size < 0 {
			return BootstrapObservation{}, ErrUnsafe
		}
		known[name] = st
	}
	value := BootstrapObservation{Kind: BootstrapEmptyDirectory}
	if unrecognized {
		value.Kind = BootstrapUnrecognizedEntries
	}
	if _, pending := known[codec.PendingName]; pending {
		// Metadata only: staged bytes are never decoded, promoted or adopted.
		// Presence requires review regardless of whether current also exists.
		value.Kind = BootstrapPendingEvidence
	} else if expected, current := known[codec.CurrentName]; current {
		revision, err := bootstrapCurrentRevision(ctx, fd, codec, expected)
		if errors.Is(err, ErrInvalid) {
			value.Kind = BootstrapInvalidPolicy
		} else if err != nil {
			return BootstrapObservation{}, err
		} else {
			value.Kind, value.Revision = BootstrapValidCurrentPolicy, revision
		}
	}
	for name, expected := range known {
		var after unix.Stat_t
		if unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil || policyStamp(expected) != policyStamp(after) {
			return BootstrapObservation{}, ErrReview
		}
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || policyStamp(before) != policyStamp(after) || !quiet() {
		return BootstrapObservation{}, ErrReview
	}
	if err := ctx.Err(); err != nil {
		return BootstrapObservation{}, err
	}
	return value, nil
}

type bootstrapContextReader struct {
	ctx    context.Context
	reader io.Reader
	fault  error
}

func (r *bootstrapContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		r.fault = err
		return 0, err
	}
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	n, err := r.reader.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		r.fault = err
	}
	return n, err
}

func bootstrapCurrentRevision[T any](ctx context.Context, directory int, codec Codec[T], expected unix.Stat_t) (uint64, error) {
	// Reuse the existing fixed-name/no-follow/no-cross-mount permission fence,
	// but never OpenWithCodec: that constructor establishes fsync boundaries.
	s := &Store[T]{dir: directory, noAtime: true, codec: codec}
	f, err := s.openCurrent()
	if err != nil {
		return 0, err
	}
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || policyStamp(before) != policyStamp(expected) {
		if f.Close() != nil {
			return 0, ErrIO
		}
		return 0, ErrReview
	}
	reader := &bootstrapContextReader{ctx: ctx, reader: io.LimitReader(f, int64(codec.MaxBytes)+1)}
	doc, decodeErr := codec.Decode(reader)
	statErr := unix.Fstat(int(f.Fd()), &after)
	closeErr := f.Close()
	if closeErr != nil || (reader.fault != nil && ctx.Err() == nil) {
		return 0, ErrIO
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if statErr != nil || policyStamp(before) != policyStamp(after) {
		return 0, ErrReview
	}
	if decodeErr != nil || codec.Validate(doc) != nil || codec.Revision(doc) == 0 {
		return 0, ErrInvalid
	}
	return codec.Revision(doc), nil
}

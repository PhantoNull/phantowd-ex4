//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package policyevidencefs observes an experimental fixed policy/record layout.
// It never initializes, writes, recovers, issues leases or admits services.
package policyevidencefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid     = errors.New("invalid policy evidence observer")
	ErrUnsafe      = errors.New("unsafe policy evidence layout")
	ErrUnsupported = errors.New("policy evidence observation unsupported")
	ErrBusy        = errors.New("policy evidence layout busy")
	ErrIO          = errors.New("policy evidence observation unavailable")
	ErrReview      = errors.New("policy evidence observer requires review")
	ErrClosed      = errors.New("policy evidence observer closed")
)

const events = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_UNMOUNT | unix.IN_IGNORED | unix.IN_Q_OVERFLOW
const required = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_MTIME | unix.STATX_CTIME | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_MNT_ID_UNIQUE
const confined = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// The pointer-only original handle carries authority; copies and zero values
// refuse. Ordinary formatting/JSON cannot disclose or transfer the lifetime.
type Observer struct{ state *state }
type stamp struct {
	mount, ino, size                    uint64
	devMajor, devMinor, uid, gid, links uint32
	mode                                uint16
	mtime, ctime                        int64
	mtimeNS, ctimeNS                    uint32
}
type object struct {
	file    *os.File
	initial stamp
}
type state struct {
	mu                          sync.Mutex
	self                        *Observer
	path, installation          string
	dirs                        [3]object // root, policy (the actual Store lock), operations
	files                       [3]object // current, intent, receipt
	names                       [3]map[string]stamp
	watch                       int
	review, closed, closeFailed bool
	uncertain                   []*os.File
	// Trusted lifetime operations, never per-call/provider/HTTP parameters.
	closeFile   func(*os.File) error
	readAt      func(*os.File, []byte, int64) (int, error)
	beforeMatch func() // nil in ordinary construction; deterministic test seam
}

// Open captures one clean absolute experimental root with fixed policy/ and
// operations/ children. Trusted stable parents, provisioning, a suitable local
// filesystem and cooperating writers remain prerequisites, not proven here.
// Requires unique (not recyclable) kernel mount IDs; no degraded fallback.
// On uncertain cleanup, returns a nonnil reviewed handle WITH error to preserve
// unattempted originals. It must never be used as a successful observation.
func Open(ctx context.Context, directory, installation string) (observer *Observer, result error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if _, err := policyevidence.Match(policyevidence.Evidence{InstallationID: installation,
		Intent: policyevidence.Slot{State: policyevidence.Absent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}, Current: policyevidence.Slot{State: policyevidence.Absent}}); err != nil ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &state{path: directory, installation: installation, watch: -1,
		closeFile: func(f *os.File) error { return f.Close() }, readAt: func(f *os.File, b []byte, off int64) (int, error) { return f.ReadAt(b, off) }}
	a := &Observer{state: s}
	s.self = a
	defer func() {
		if result != nil {
			if a.Close() != nil {
				observer = a
				result = errors.Join(ErrReview, result)
			}
		}
	}()
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrUnsupported
	}
	var err error
	s.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, ErrIO
	}
	for i, name := range []string{directory, "policy", "operations"} {
		parent, resolve := unix.AT_FDCWD, uint64(unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
		if i != 0 {
			parent, resolve = int(s.dirs[0].file.Fd()), confined
		}
		f, err := openFile(parent, name, true, resolve)
		if err != nil {
			return nil, err
		}
		s.dirs[i].file = f
		st, err := statFD(f)
		if err != nil {
			return nil, err
		}
		if !owned(st, true) || (i != 0 && !sameMedium(st, s.dirs[0].initial)) {
			return nil, ErrUnsafe
		}
		for j := 0; j < i; j++ {
			if st.ino == s.dirs[j].initial.ino && sameMedium(st, s.dirs[j].initial) {
				return nil, ErrUnsafe
			}
		}
		s.dirs[i].initial = st
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, ErrBusy
			}
			return nil, ErrIO
		}
		if err := s.watchFile(f, true); err != nil {
			return nil, err
		}
	}
	for i := range s.dirs {
		s.names[i], err = s.census(ctx, i)
		if err != nil {
			return nil, err
		}
	}
	for i, spec := range roles {
		expected, present := s.names[spec.parent][spec.name]
		if !present {
			continue
		}
		if expected.size == 0 || expected.size > uint64(spec.limit) {
			return nil, ErrUnsafe
		}
		f, err := openFile(int(s.dirs[spec.parent].file.Fd()), spec.name, false, confined)
		if err != nil {
			return nil, err
		}
		s.files[i].file = f
		st, err := statFD(f)
		if err != nil {
			return nil, err
		}
		if st != expected {
			return nil, ErrReview
		}
		s.files[i].initial = st
		if err := s.watchFile(f, false); err != nil {
			return nil, err
		}
	}
	if err := s.verify(ctx); err != nil {
		return nil, err
	}
	_, s.review = s.names[1][".nas-services.pending"] // metadata only; never read
	return a, nil
}

var roles = [...]struct {
	parent int
	name   string
	limit  int
}{
	{1, "nas-services.json", naspolicy.MaxInputBytes}, {2, "intent.json", policyevidence.MaxRecordBytes}, {2, "receipt.json", policyevidence.MaxRecordBytes},
}

func openFile(parent int, name string, dir bool, resolve uint64) (*os.File, error) {
	flags := uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_CLOEXEC | unix.O_NONBLOCK)
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: flags, Resolve: resolve})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, ErrUnsafe
		}
		if errors.Is(err, unix.ENOSYS) {
			return nil, ErrUnsupported
		}
		return nil, ErrIO
	}
	return os.NewFile(uintptr(fd), "policy-evidence-original"), nil
}
func statAt(fd int, name string, flags int) (stamp, error) {
	var x unix.Statx_t
	if unix.Statx(fd, name, flags|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &x) != nil {
		return stamp{}, ErrIO
	}
	if x.Mask&required != required || x.Mnt_id == 0 {
		return stamp{}, ErrUnsupported
	}
	return stamp{x.Mnt_id, x.Ino, x.Size, x.Dev_major, x.Dev_minor, x.Uid, x.Gid, x.Nlink, x.Mode, x.Mtime.Sec, x.Ctime.Sec, x.Mtime.Nsec, x.Ctime.Nsec}, nil
}
func statFD(f *os.File) (stamp, error) { return statAt(int(f.Fd()), "", unix.AT_EMPTY_PATH) }
func owned(st stamp, dir bool) bool {
	kind, mode := uint16(unix.S_IFREG), uint16(0600)
	if dir {
		kind, mode = unix.S_IFDIR, 0700
	}
	return st.mode&unix.S_IFMT == kind && st.mode&07777 == mode && st.uid == uint32(os.Geteuid()) && (dir || st.links == 1)
}
func sameMedium(a, b stamp) bool {
	return a.mount == b.mount && a.devMajor == b.devMajor && a.devMinor == b.devMinor
}
func (s *state) watchFile(f *os.File, dir bool) error {
	mask := uint32(events)
	if dir {
		mask |= unix.IN_ONLYDIR
	}
	if wd, err := unix.InotifyAddWatch(s.watch, "/proc/self/fd/"+strconv.Itoa(int(f.Fd())), mask); err != nil || wd < 0 {
		return ErrIO
	}
	return nil
}
func (s *state) quiet() bool {
	var buffer [4096]byte
	n, err := unix.Read(s.watch, buffer[:])
	return n == -1 && errors.Is(err, unix.EAGAIN)
}
func (s *state) closeTemporary(f *os.File) error {
	if s.closeFile(f) != nil {
		s.review, s.closeFailed = true, true
		s.uncertain = append(s.uncertain, f)
		return ErrReview
	}
	return nil
}

// A separate confined cursor never replaces the locked original directory FD.
func (s *state) census(ctx context.Context, index int) (found map[string]stamp, result error) {
	parent := s.dirs[index]
	cursor, err := openFile(int(parent.file.Fd()), ".", true, confined)
	if err != nil {
		return nil, err
	}
	defer func() {
		if s.closeTemporary(cursor) != nil {
			found, result = nil, ErrReview
		}
	}()
	st, err := statFD(cursor)
	if err != nil || st != parent.initial {
		return nil, ErrReview
	}
	allowed := [...]map[string]bool{{"policy": true, "operations": true}, {"nas-services.json": true, ".nas-services.pending": true}, {"intent.json": true, "receipt.json": true}}
	found = make(map[string]stamp, 2)
	for len(found) <= 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names, err := cursor.Readdirnames(1)
		if len(names) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(names) != 1 {
			return nil, ErrIO
		}
		name := names[0]
		if _, duplicate := found[name]; duplicate || !allowed[index][name] {
			return nil, ErrUnsafe
		}
		st, err := statAt(int(parent.file.Fd()), name, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return nil, err
		}
		if !owned(st, index == 0) || !sameMedium(st, s.dirs[0].initial) {
			return nil, ErrUnsafe
		}
		found[name] = st
	}
	if index == 0 && (len(found) != 2 || found["policy"] != s.dirs[1].initial || found["operations"] != s.dirs[2].initial) {
		return nil, ErrReview
	}
	st, err = statFD(parent.file)
	if err != nil || st != parent.initial {
		return nil, ErrReview
	}
	return found, nil
}

func (s *state) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.quiet() {
		return ErrReview
	}
	// Re-open only as a temporary path witness, not a replacement authority.
	witness, err := openFile(unix.AT_FDCWD, s.path, true, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return err
	}
	st, statErr := statFD(witness)
	closeErr := s.closeTemporary(witness)
	if statErr != nil || closeErr != nil || st != s.dirs[0].initial {
		return ErrReview
	}
	for i, dir := range s.dirs {
		st, err := statFD(dir.file)
		if err != nil || st != dir.initial {
			return ErrReview
		}
		found, err := s.census(ctx, i)
		if err != nil {
			return err
		}
		if len(found) != len(s.names[i]) {
			return ErrReview
		}
		for name, expected := range s.names[i] {
			if actual, ok := found[name]; !ok || actual != expected {
				return ErrReview
			}
		}
	}
	for _, f := range s.files {
		if f.file != nil {
			st, err := statFD(f.file)
			if err != nil || st != f.initial {
				return ErrReview
			}
		}
	}
	if !s.quiet() {
		return ErrReview
	}
	return ctx.Err()
}

func (a *Observer) valid() bool { return a != nil && a.state != nil && a.state.self == a }

// Observe re-reads original file objects under all three original locks. Only
// the existing redacted pure diagnosis escapes; every kind grants no action.
func (a *Observer) Observe(ctx context.Context) (policyevidence.Diagnosis, error) {
	if !a.valid() || ctx == nil {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return policyevidence.Diagnosis{}, err
	}
	s := a.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeFailed || s.review {
		return policyevidence.Diagnosis{}, ErrReview
	}
	if s.closed {
		return policyevidence.Diagnosis{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return policyevidence.Diagnosis{}, err
	}
	fail := func(err error) (policyevidence.Diagnosis, error) {
		s.review = true
		return policyevidence.Diagnosis{}, errors.Join(ErrReview, err, ctx.Err())
	}
	if err := s.verify(ctx); err != nil {
		return fail(err)
	}
	var slots [3]policyevidence.Slot
	defer func() {
		for i := range slots {
			clear(slots[i].Data)
		}
	}()
	for i, f := range s.files {
		slots[i].State = policyevidence.Absent
		if f.file == nil {
			continue
		}
		slots[i].State = policyevidence.Present
		slots[i].Data = make([]byte, int(f.initial.size))
		for off := 0; off < len(slots[i].Data); {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			end := min(off+8192, len(slots[i].Data))
			n, err := s.readAt(f.file, slots[i].Data[off:end], int64(off))
			if err != nil || n != end-off {
				return fail(ErrIO)
			}
			off = end
		}
		var extra [1]byte
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if n, err := s.readAt(f.file, extra[:], int64(f.initial.size)); n != 0 || !errors.Is(err, io.EOF) {
			return fail(ErrIO)
		}
	}
	if s.beforeMatch != nil {
		s.beforeMatch()
	}
	d, err := policyevidence.Match(policyevidence.Evidence{InstallationID: s.installation, Current: slots[0], Intent: slots[1], Receipt: slots[2]})
	if err != nil {
		return fail(ErrInvalid)
	}
	if err := s.verify(ctx); err != nil {
		return fail(err)
	}
	return d, nil
}

// Close releases only this observer; it never reconciles evidence. First close
// uncertainty is terminal: retain remaining originals, never retry a raw FD.
func (a *Observer) Close() error {
	if !a.valid() {
		return ErrInvalid
	}
	s := a.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeFailed {
		return ErrReview
	}
	if s.closed {
		return nil
	}
	for _, roster := range []*[3]object{&s.files, &s.dirs} {
		for i := len(roster) - 1; i >= 0; i-- {
			if roster[i].file != nil {
				if s.closeFile(roster[i].file) != nil {
					s.review, s.closeFailed = true, true
					return ErrReview
				}
				roster[i].file = nil
			}
		}
	}
	if s.watch >= 0 {
		if unix.Close(s.watch) != nil {
			s.review, s.closeFailed = true, true
			return ErrReview
		}
		s.watch = -1
	}
	s.closed = true
	return nil
}
func (Observer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-evidence-observer{private}")
}
func (Observer) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*Observer) UnmarshalJSON([]byte) error  { return ErrInvalid }

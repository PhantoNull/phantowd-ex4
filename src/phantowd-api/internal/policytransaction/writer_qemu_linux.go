//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"golang.org/x/sys/unix"
)

const rootEvents = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_UNMOUNT | unix.IN_IGNORED | unix.IN_Q_OVERFLOW | unix.IN_ONLYDIR
const below = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

type rootStamp struct {
	ino, mount             uint64
	major, minor, uid, gid uint32
	mode                   uint16
	mtime, ctime           unix.StatxTimestamp
}

func rootIdentity(f *os.File) (rootStamp, error) {
	var x unix.Statx_t
	const required = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_INO | unix.STATX_MTIME | unix.STATX_CTIME | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &x) != nil {
		return rootStamp{}, ErrReview
	}
	if x.Mask&required != required || x.Mnt_id == 0 {
		return rootStamp{}, ErrUnsupported
	}
	if x.Mode&unix.S_IFMT != unix.S_IFDIR || x.Mode&07777 != 0700 || x.Uid != uint32(os.Geteuid()) {
		return rootStamp{}, ErrReview
	}
	return rootStamp{x.Ino, x.Mnt_id, x.Dev_major, x.Dev_minor, x.Uid, x.Gid, x.Mode, x.Mtime, x.Ctime}, nil
}
func rootOpen(parent int, name string, resolve uint64) (*os.File, error) {
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_CLOEXEC, Resolve: resolve})
	if err != nil {
		return nil, ErrReview
	}
	return os.NewFile(uintptr(fd), "experimental-policy-original"), nil
}
func policyCodec() revisionstore.Codec[naspolicy.Config] {
	return revisionstore.Codec[naspolicy.Config]{CurrentName: "nas-services.json", PendingName: ".nas-services.pending", MaxBytes: naspolicy.MaxInputBytes,
		Decode: naspolicy.Decode, Validate: naspolicy.Config.Validate, Revision: func(c naspolicy.Config) uint64 { return c.Revision }}
}
func operationCodec() revisionstore.Codec[bundle] {
	return revisionstore.Codec[bundle]{CurrentName: "operation.json", PendingName: ".operation.pending", MaxBytes: maxBundleBytes,
		Decode: decodeBundle, Validate: bundle.validate, Revision: func(b bundle) uint64 { return b.revision }}
}

// No product constructor exists. This private lifetime can only be created over
// a newly generated tmpfs namespace by this QEMU-only package. No caller path,
// existing state, consumer, HTTP parameter or per-operation backend is accepted.
type writer struct {
	mu                                                *sync.Mutex
	self                                              *writer
	root                                              *os.File
	path, installation                                string
	initial                                           rootStamp
	watch                                             int
	policy                                            *revisionstore.Store[naspolicy.Config]
	journal                                           *revisionstore.Store[bundle]
	history                                           *historyJournal
	checkpoint                                        []byte
	base                                              []byte
	attempted, review, confirmed, closed, closeFailed bool
	uncertain                                         []*os.File
	// Captured real Store methods. Private fixtures may install deterministic
	// wrappers before an operation; no exported/per-call injection API exists.
	policyWrite  func(uint64, naspolicy.Config) error
	journalWrite func(uint64, bundle) error
	policyRead   func() (naspolicy.Config, []byte, error)
	boundary     func(string)
}
type localOutcome struct{ revision uint64 }

func (localOutcome) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (localOutcome) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "local-policy-outcome{private}")
}
func (writer) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (writer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "experimental-policy-writer{private}")
}

func newDisposable(ctx context.Context, id string, initial naspolicy.Config) (*writer, error) {
	return newDisposableWithCrash(ctx, id, initial, nil)
}

// Private fixture-only construction input, fixed before any Store is published;
// ordinary callers always pass nil. It cannot be selected by an operation/API.
type disposableCrash struct {
	role, point string
	gate        func()
}

func newDisposableWithCrash(ctx context.Context, id string, initial naspolicy.Config, crash *disposableCrash) (*writer, error) {
	return newDisposableMode(ctx, id, initial, crash, false, nil)
}

func newDisposableHistory(ctx context.Context, id string, initial naspolicy.Config) (*writer, error) {
	return newDisposableMode(ctx, id, initial, nil, true, nil)
}

func newDisposableHistoryWithCrash(ctx context.Context, id string, initial naspolicy.Config, plan *disposableCrash) (*writer, error) {
	return newDisposableMode(ctx, id, initial, nil, true, plan)
}

func newDisposableMode(ctx context.Context, id string, initial naspolicy.Config, crash *disposableCrash, history bool, historyPlan *disposableCrash) (*writer, error) {
	if history && crash != nil {
		return nil, ErrInvalid
	}
	historyCrash, historyErr := copyHistoryCrash(historyPlan, true)
	if historyErr != nil || !history && historyCrash != nil {
		return nil, ErrInvalid
	}
	var profile revisionstore.QEMUCommitCrash
	if historyCrash != nil && historyCrash.role == "policy" {
		var e error
		profile, e = revisionstore.NewQEMUThirdRevisionCrash(historyCrash.point, historyCrash.gate)
		if e != nil {
			return nil, ErrInvalid
		}
	}
	if crash != nil {
		target := uint64(2)
		if crash.role == "intent" {
			target = 1
		} else if crash.role != "policy" && crash.role != "receipt" {
			return nil, ErrInvalid
		}
		var e error
		profile, e = revisionstore.NewQEMUCommitCrash(target, crash.point, crash.gate)
		if e != nil {
			return nil, ErrInvalid
		}
	}
	if ctx == nil || initial.Revision != 1 || initial.Validate() != nil {
		return nil, ErrInvalid
	}
	if _, err := policyevidence.Match(policyevidence.Evidence{InstallationID: id,
		Current: policyevidence.Slot{State: policyevidence.Absent}, Intent: policyevidence.Slot{State: policyevidence.Absent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}}); err != nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(initial)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(encoded)
	owned, err := naspolicy.Decode(bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrInvalid
	}
	var fs, proc unix.Statfs_t
	if unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrUnsupported
	}
	// Probe mandatory unique-ID support BEFORE creating any namespace. /tmp is
	// not private, so use the raw support bit here, not owned-directory admission.
	var probe unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, "/tmp", unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &probe) != nil || probe.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || probe.Mnt_id == 0 {
		return nil, ErrUnsupported
	}
	dir, err := os.MkdirTemp("/tmp", "phantowd-transaction-")
	if err != nil {
		return nil, ErrReview
	}
	for _, name := range []string{"policy", "operations"} {
		if os.Mkdir(filepath.Join(dir, name), 0700) != nil {
			// Only these known empty fixture directories, never recursive removal.
			_ = os.Remove(filepath.Join(dir, "operations"))
			_ = os.Remove(filepath.Join(dir, "policy"))
			_ = os.Remove(dir)
			return nil, ErrReview
		}
	}
	f, err := rootOpen(unix.AT_FDCWD, dir, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		_ = os.Remove(filepath.Join(dir, "operations"))
		_ = os.Remove(filepath.Join(dir, "policy"))
		_ = os.Remove(dir)
		return nil, ErrReview
	}
	w := &writer{mu: &sync.Mutex{}, root: f, path: dir, installation: id, watch: -1}
	w.self = w
	fail := func() (*writer, error) { w.review = true; return w, ErrReview }
	w.initial, err = rootIdentity(f)
	if err != nil {
		return fail()
	}
	if unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail()
	}
	if crash != nil && crash.role == "policy" || historyCrash != nil && historyCrash.role == "policy" {
		w.policy, err = revisionstore.OpenAnchoredQEMUCrashWithCodec(f, "policy", policyCodec(), profile)
	} else {
		w.policy, err = revisionstore.OpenAnchoredWithCodec(f, "policy", policyCodec())
	}
	if err != nil {
		return fail()
	}
	if history {
		journalPlan := historyCrash
		if journalPlan != nil && journalPlan.role == "policy" {
			journalPlan = nil
		}
		w.history, err = newHistoryJournalWithCrash(f, journalPlan)
	} else if crash != nil && crash.role != "policy" {
		w.journal, err = revisionstore.OpenAnchoredQEMUCrashWithCodec(f, "operations", operationCodec(), profile)
	} else {
		w.journal, err = revisionstore.OpenAnchoredWithCodec(f, "operations", operationCodec())
	}
	if err != nil {
		return fail()
	}
	w.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fail()
	}
	if wd, e := unix.InotifyAddWatch(w.watch, "/proc/self/fd/"+strconv.Itoa(int(f.Fd())), rootEvents); e != nil || wd < 0 {
		return fail()
	}
	// The only initialized base is one created and confirmed HERE, under the
	// original locks. No existing file's presence is interpreted as confirmation.
	if w.policy.Commit(0, owned) != nil {
		return fail()
	}
	_, w.base, err = w.policy.LoadExact()
	if err != nil || !bytes.Equal(w.base, encoded) || w.guard(ctx) != nil {
		return fail()
	}
	w.policyWrite = w.policy.Commit
	if w.journal != nil {
		w.journalWrite = w.journal.Commit
	}
	if history {
		w.checkpoint = bytes.Clone(w.base)
	}
	w.policyRead = w.policy.LoadExact
	return w, nil
}

func rootCensus(root *os.File) bool {
	f, err := rootOpen(int(root.Fd()), ".", below)
	if err != nil {
		return false
	}
	names, err := f.Readdirnames(3)
	complete := errors.Is(err, io.EOF)
	if err == nil && len(names) < 3 {
		more, e := f.Readdirnames(1)
		names = append(names, more...)
		complete = errors.Is(e, io.EOF) && len(more) == 0
	}
	closeErr := f.Close()
	return closeErr == nil && complete && len(names) == 2 &&
		(names[0] == "policy" && names[1] == "operations" || names[1] == "policy" && names[0] == "operations")
}
func (w *writer) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	quiet := func() bool {
		var buf [4096]byte
		n, e := unix.Read(w.watch, buf[:])
		return n == -1 && errors.Is(e, unix.EAGAIN)
	}
	if !quiet() {
		return ErrReview
	}
	held, err := rootIdentity(w.root)
	if err != nil || held != w.initial || !rootCensus(w.root) {
		return ErrReview
	}
	f, err := rootOpen(unix.AT_FDCWD, w.path, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return ErrReview
	}
	named, statErr := rootIdentity(f)
	if f.Close() != nil {
		w.uncertain = append(w.uncertain, f)
		w.closeFailed = true
		return ErrReview
	}
	if statErr != nil || named != w.initial || !quiet() {
		return ErrReview
	}
	return ctx.Err()
}
func (w *writer) poison(ctx context.Context) error {
	w.review = true
	return errors.Join(ErrReview, ctx.Err())
}
func (w *writer) at(name string) {
	if w.boundary != nil {
		w.boundary(name)
	}
}
func (w *writer) journalMatches(expected bundle) bool {
	loaded, raw, err := w.journal.LoadExact()
	defer loaded.clear()
	defer clear(raw)
	encoded, e := json.Marshal(expected)
	defer clear(encoded)
	return err == nil && e == nil && bytes.Equal(raw, encoded)
}
func (w *writer) execute(ctx context.Context, next naspolicy.Config) (localOutcome, error) {
	if w == nil || w.self != w || ctx == nil {
		return localOutcome{}, ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.history != nil {
		return localOutcome{}, ErrInvalid
	}
	if w.closed || w.closeFailed || w.review {
		return localOutcome{}, ErrReview
	}
	if w.attempted {
		return localOutcome{}, ErrAttempted
	}
	if err := ctx.Err(); err != nil {
		return localOutcome{}, err
	}
	if w.guard(ctx) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	previous, raw, err := w.policyRead()
	defer clear(raw)
	if err != nil || !bytes.Equal(raw, w.base) {
		return localOutcome{}, w.poison(ctx)
	}
	b, record, err := w.journal.LoadExact()
	defer b.clear()
	defer clear(record)
	if err != revisionstore.ErrNotInitialized {
		return localOutcome{}, w.poison(ctx)
	}
	p, err := policyevidence.Prepare(w.installation, raw, next)
	if err != nil {
		if errors.Is(err, policyevidence.ErrPreparation) {
			return localOutcome{}, policyevidence.ErrPreparation
		}
		return localOutcome{}, ErrInvalid
	}
	candidate, err := p.CandidateBytes()
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer clear(candidate)
	owned, err := naspolicy.Decode(bytes.NewReader(candidate))
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	intent, err := intentBundle(w.installation, p)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer intent.clear()
	if err := ctx.Err(); err != nil {
		return localOutcome{}, err
	}
	if w.guard(ctx) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	// From here ANY failure is an admitted uncertain operation, even before the
	// first open/write syscall. No second operation, fresh ID or retry is allowed.
	w.attempted = true
	w.at("before-intent")
	if w.guard(ctx) != nil || w.journalWrite(0, intent) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-intent")
	if w.guard(ctx) != nil || !w.journalMatches(intent) {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("before-policy")
	if w.guard(ctx) != nil || w.policyWrite(previous.Revision, owned) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-policy")
	if w.guard(ctx) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	_, published, err := w.policyRead()
	defer clear(published)
	if err != nil || !bytes.Equal(published, candidate) {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-readback")
	if w.guard(ctx) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	confirmed, err := confirmedBundle(intent)
	if err != nil {
		return localOutcome{}, w.poison(ctx)
	}
	defer confirmed.clear()
	w.at("before-receipt")
	if w.guard(ctx) != nil || !w.policyMatches(candidate) || w.journalWrite(1, confirmed) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-receipt")
	if w.guard(ctx) != nil || !w.journalMatches(confirmed) || !w.policyMatches(candidate) {
		return localOutcome{}, w.poison(ctx)
	}
	// This verifies local return boundaries only. No HTTP response, consumer or
	// service exists here; a surviving confirmation record cannot prove delivery.
	if w.guard(ctx) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.confirmed = true
	return localOutcome{revision: owned.Revision}, nil
}

func (w *writer) policyMatches(candidate []byte) bool {
	_, raw, err := w.policyRead()
	defer clear(raw)
	return err == nil && bytes.Equal(raw, candidate)
}

func (w *writer) close() error {
	if w == nil || w.self != w {
		return ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closeFailed {
		return ErrReview
	}
	if w.closed {
		return nil
	}
	fail := func() error { w.review = true; w.closeFailed = true; return ErrReview }
	if w.history != nil && w.history.close() != nil {
		return fail()
	}
	if w.journal != nil && w.journal.Close() != nil {
		return fail()
	}
	if w.policy != nil && w.policy.Close() != nil {
		return fail()
	}
	if w.watch >= 0 {
		fd := w.watch
		w.watch = -1
		if unix.Close(fd) != nil {
			return fail()
		}
	}
	if w.root.Close() != nil {
		return fail()
	}
	w.closed = true
	clear(w.base)
	clear(w.checkpoint)
	return nil
}

// Fixture disposal is explicitly separate from Close and never product
// recovery. It runs only after verified closure, targets this generated root,
// refuses unknown entries/mounts and unlinks only the four fixed Store names.
func (w *writer) discard() error {
	if w == nil || w.self != w {
		return ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed || w.closeFailed || filepath.Dir(w.path) != "/tmp" || !strings.HasPrefix(filepath.Base(w.path), "phantowd-transaction-") {
		return ErrReview
	}
	f, err := rootOpen(unix.AT_FDCWD, w.path, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return ErrReview
	}
	defer f.Close()
	id, err := rootIdentity(f)
	// Fixture root mtimes may differ after a deliberate structural fault.
	id.mtime, id.ctime = w.initial.mtime, w.initial.ctime
	if err != nil || id != w.initial || !rootCensus(f) {
		return ErrReview
	}
	for _, spec := range []struct {
		dir                        string
		codecCurrent, codecPending string
	}{{"policy", "nas-services.json", ".nas-services.pending"}, {"operations", "operation.json", ".operation.pending"}} {
		child, e := rootOpen(int(f.Fd()), spec.dir, below)
		if e != nil {
			return ErrReview
		}
		limit := 3
		if spec.dir == "operations" && w.history != nil {
			limit = policyevidence.MaxHistoryOperations + 2
		}
		names, readErr := child.Readdirnames(limit)
		complete := errors.Is(readErr, io.EOF)
		if readErr == nil && len(names) < limit {
			more, e := child.Readdirnames(1)
			names = append(names, more...)
			complete = errors.Is(e, io.EOF) && len(more) == 0
		}
		if !complete || len(names) >= limit {
			_ = child.Close()
			return ErrReview
		}
		for _, name := range names {
			var st unix.Stat_t
			allowed := name == spec.codecCurrent || name == spec.codecPending
			if spec.dir == "operations" && w.history != nil {
				allowed = name == journalPending || w.history.attemptedNames[name]
			}
			if !allowed || unix.Fstatat(int(child.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || unix.Unlinkat(int(child.Fd()), name, 0) != nil {
				_ = child.Close()
				return ErrReview
			}
		}
		if child.Close() != nil || unix.Unlinkat(int(f.Fd()), spec.dir, unix.AT_REMOVEDIR) != nil {
			return ErrReview
		}
	}
	// os.Remove only removes this now-empty generated directory, never recursively.
	return os.Remove(w.path)
}

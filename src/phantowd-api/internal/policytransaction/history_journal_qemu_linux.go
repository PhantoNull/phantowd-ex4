//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

const journalPending = ".history.pending"

type journalObject struct {
	file  *os.File
	stamp journalStamp
	wire  []byte
}
type journalStamp struct {
	dev, ino       uint64
	mode, uid, gid uint32
	links          uint64
	size           int64
	mtime, ctime   unix.Timespec
}

func journalStat(f *os.File) (journalStamp, error) {
	var s unix.Stat_t
	if unix.Fstat(int(f.Fd()), &s) != nil {
		return journalStamp{}, ErrReview
	}
	return journalStamp{uint64(s.Dev), s.Ino, s.Mode, s.Uid, s.Gid, uint64(s.Nlink), s.Size, s.Mtim, s.Ctim}, nil
}
func privateDirectory(s journalStamp) bool {
	return s.mode&unix.S_IFMT == unix.S_IFDIR && s.mode&07777 == 0700 && s.uid == uint32(os.Geteuid())
}
func sameJournalDirectory(a, b journalStamp) bool {
	return privateDirectory(a) && privateDirectory(b) && a.dev == b.dev && a.ino == b.ino && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid
}

// Private QEMU-only primitive. The enclosing root Owner supplies the original
// borrowed parent, its unique mount/path/watch authority and serialized access.
// This constructor owns a NEW child/flock and admits only an empty namespace.
// It never opens existing history or acquires policy/service authority.
type historyJournal struct {
	self                        *historyJournal
	parent, dir                 *os.File
	parentID, dirID             journalStamp
	watch, directoryWatch       int
	records                     map[string]journalObject
	attemptedNames              map[string]bool // fixture disposal only, never recovery
	inflight                    string
	bytes                       int
	review, closed, closeFailed bool
	uncertain                   []*os.File
	retired                     []journalObject // metadata retained on ambiguous replacement close
	closeFile                   func(*os.File) error
	watchFile                   func(*os.File) error // captured fixture-only boundary, never per-call
	crash                       *disposableCrash
	crashFired                  bool
}

func newHistoryJournal(parent *os.File) (*historyJournal, error) {
	return newHistoryJournalWithCrash(parent, nil)
}

func newHistoryJournalWithCrash(parent *os.File, plan *disposableCrash) (*historyJournal, error) {
	crash, err := copyHistoryCrash(plan, false)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, ErrInvalid
	}
	p, err := journalStat(parent)
	if err != nil || !privateDirectory(p) {
		return nil, ErrInvalid
	}
	dir, err := rootOpen(int(parent.Fd()), "operations", below)
	if err != nil {
		return nil, err
	}
	j := &historyJournal{parent: parent, dir: dir, parentID: p, watch: -1, records: make(map[string]journalObject), attemptedNames: make(map[string]bool), closeFile: func(f *os.File) error { return f.Close() }}
	j.self = j
	j.crash = crash
	j.watchFile = func(f *os.File) error {
		_, err := unix.InotifyAddWatch(j.watch, "/proc/self/fd/"+strconv.Itoa(int(f.Fd())), rootEvents&^unix.IN_ONLYDIR)
		return err
	}
	fail := func() (*historyJournal, error) { j.review = true; return j, ErrReview }
	j.dirID, err = journalStat(dir)
	if err != nil || !privateDirectory(j.dirID) || j.dirID.dev != p.dev || unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail()
	}
	j.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fail()
	}
	j.directoryWatch, err = unix.InotifyAddWatch(j.watch, "/proc/self/fd/"+strconv.Itoa(int(dir.Fd())), rootEvents)
	if err != nil || j.directoryWatch < 0 || j.check() != nil {
		return fail()
	}
	return j, nil
}
func (j *historyJournal) fail() error { j.review = true; return ErrReview }
func (j *historyJournal) quiet() bool {
	var buf [4096]byte
	n, err := unix.Read(j.watch, buf[:])
	return n == -1 && errors.Is(err, unix.EAGAIN)
}
func (j *historyJournal) closeTemporary(f *os.File) error {
	if j.closeFile(f) != nil {
		j.uncertain = append(j.uncertain, f)
		j.closeFailed = true
		return j.fail()
	}
	return nil
}
func (j *historyJournal) namesMatch() bool {
	f, err := rootOpen(int(j.dir.Fd()), ".", below)
	if err != nil {
		return false
	}
	names, readErr := f.Readdirnames(policyevidence.MaxHistoryOperations + 1)
	complete := errors.Is(readErr, io.EOF)
	if readErr == nil && len(names) <= policyevidence.MaxHistoryOperations {
		more, e := f.Readdirnames(1)
		names = append(names, more...)
		complete = errors.Is(e, io.EOF) && len(more) == 0
	}
	closeErr := j.closeTemporary(f)
	if closeErr != nil || !complete || len(names) != len(j.records) {
		return false
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if _, present := j.records[name]; !present || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func (j *historyJournal) bound() bool {
	p, err := journalStat(j.parent)
	if err != nil || !sameJournalDirectory(p, j.parentID) {
		return false
	}
	held, err := journalStat(j.dir)
	if err != nil || !sameJournalDirectory(held, j.dirID) {
		return false
	}
	named, err := rootOpen(int(j.parent.Fd()), "operations", below)
	if err != nil {
		return false
	}
	n, statErr := journalStat(named)
	closeErr := j.closeTemporary(named)
	return statErr == nil && closeErr == nil && n == held
}
func (j *historyJournal) check() error {
	if j == nil || j.self != j {
		return ErrInvalid
	}
	if j.closed || j.closeFailed || j.review {
		return ErrReview
	}
	if !j.quiet() || !j.bound() || !j.namesMatch() {
		return j.fail()
	}
	dir, err := journalStat(j.dir)
	if err != nil || dir != j.dirID {
		return j.fail()
	}
	for name, record := range j.records {
		held, err := journalStat(record.file)
		var named unix.Stat_t
		if err != nil || held != record.stamp || unix.Fstatat(int(j.dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(named.Dev) != held.dev || named.Ino != held.ino {
			return j.fail()
		}
	}
	if !j.quiet() {
		return j.fail()
	}
	return nil
}
func (j *historyJournal) observe() ([]NamedBundleObservation, error) {
	if err := j.check(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(j.records))
	for name := range j.records {
		names = append(names, name)
	}
	slices.Sort(names)
	entries := make([]NamedBundleObservation, len(names))
	for i, name := range names {
		r := j.records[name]
		data := make([]byte, len(r.wire))
		n, readErr := r.file.ReadAt(data, 0)
		var extra [1]byte
		more, endErr := r.file.ReadAt(extra[:], int64(len(data)))
		if readErr != nil || n != len(data) || more != 0 || !errors.Is(endErr, io.EOF) || !bytes.Equal(data, r.wire) {
			clear(data)
			for _, entry := range entries {
				clear(entry.Operation.Data)
			}
			return nil, j.fail()
		}
		entries[i] = NamedBundleObservation{Name: name, Operation: policyevidence.Slot{State: policyevidence.Present, Data: data}}
	}
	if j.check() != nil {
		for _, entry := range entries {
			clear(entry.Operation.Data)
		}
		return nil, ErrReview
	}
	return entries, nil
}
func (j *historyJournal) begin(name string, b bundle) error {
	if err := j.check(); err != nil {
		return err
	}
	if j.inflight != "" {
		return j.fail()
	}
	if len(j.records) >= policyevidence.MaxHistoryOperations {
		return ErrInvalid
	}
	if _, exists := j.records[name]; exists {
		return ErrInvalid
	}
	if b.revision != 1 {
		return ErrInvalid
	}
	return j.publish(name, b, false)
}
func (j *historyJournal) confirm(name string, b bundle) error {
	if err := j.check(); err != nil {
		return err
	}
	old, found := j.records[name]
	if !found || j.inflight != name || b.revision != 2 {
		return ErrInvalid
	}
	previous, err := decodeBundle(bytes.NewReader(old.wire))
	if err != nil {
		return j.fail()
	}
	defer previous.clear()
	if previous.installation != b.installation || !bytes.Equal(previous.base, b.base) || !bytes.Equal(previous.intent, b.intent) {
		return ErrInvalid
	}
	return j.publish(name, b, true)
}

// Require the exact five directory events generated by this fixed publication.
// No drain-and-ignore, watch reset, unknown-name waiver or history-event masking.
// Coalescing/queue/kernel behavior outside this profile fails closed.
func (j *historyJournal) publicationEvents(name string) bool {
	var buf [4096]byte
	n, err := unix.Read(j.watch, buf[:])
	if err != nil || n <= 0 {
		return false
	}
	step, cookie := 0, uint32(0)
	for off := 0; off < n; {
		if n-off < unix.SizeofInotifyEvent || step >= 5 {
			return false
		}
		wd := int(int32(binary.NativeEndian.Uint32(buf[off:])))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		c := binary.NativeEndian.Uint32(buf[off+8:])
		length := int(binary.NativeEndian.Uint32(buf[off+12:]))
		if length <= 0 || length > n-off-unix.SizeofInotifyEvent {
			return false
		}
		raw := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+length]
		end := bytes.IndexByte(raw, 0)
		if end < 0 || wd != j.directoryWatch {
			return false
		}
		expectedMask, expectedName := []uint32{unix.IN_CREATE, unix.IN_MODIFY, unix.IN_CLOSE_WRITE, unix.IN_MOVED_FROM, unix.IN_MOVED_TO}[step], journalPending
		if step == 4 {
			expectedName = name
		}
		if mask != expectedMask || string(raw[:end]) != expectedName || step < 3 && c != 0 {
			return false
		}
		if step == 3 {
			cookie = c
		}
		if step >= 3 && (cookie == 0 || c != cookie) {
			return false
		}
		step++
		off += unix.SizeofInotifyEvent + length
	}
	return step == 5 && j.quiet()
}
func (j *historyJournal) publish(name string, b bundle, replacing bool) error {
	if !IsHistoryRecordName(name) || b.validate() != nil {
		return ErrInvalid
	}
	i, err := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
	if err != nil || !i.MatchesOperationID(name[:32]) {
		return ErrInvalid
	}
	wire, err := json.Marshal(b)
	if err != nil {
		return ErrInvalid
	}
	defer clear(wire)
	old := j.records[name]
	if j.bytes-len(old.wire)+len(wire) > policyevidence.MaxHistoryInputBytes {
		return ErrInvalid
	}
	// Every effect attempt is fenced by the enclosing Owner, including failure
	// of this first open. No failed publication removes pending evidence.
	ordinal := len(j.records)
	if !replacing {
		ordinal++
	}
	active := j.crash != nil && ordinal == 2 && (j.crash.role == "intent" && b.revision == 1 || j.crash.role == "receipt" && b.revision == 2)
	fire := func(point string) bool {
		if !active || j.crashFired || j.crash.point != point {
			return false
		}
		j.crashFired = true
		j.crash.gate()
		return true // A returning gate is NEVER successful publication.
	}
	j.attemptedNames[name] = true
	fd, err := unix.Openat2(int(j.dir.Fd()), journalPending, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC, Mode: 0600, Resolve: below})
	if err != nil {
		return j.fail()
	}
	f := os.NewFile(uintptr(fd), "experimental-history-pending")
	input := wire
	partial := active && j.crash.point == "partial-write"
	if partial {
		input = wire[:8]
	}
	n, writeErr := f.Write(input)
	if writeErr == nil && n == len(input) {
		if partial {
			fire("partial-write")
			writeErr = ErrReview
		} else if fire("full-write") {
			writeErr = ErrReview
		}
	}
	var syncErr error
	if writeErr == nil && n == len(wire) {
		syncErr = f.Sync()
		if syncErr == nil && fire("file-sync") {
			syncErr = ErrReview
		}
	}
	written, statErr := journalStat(f)
	closeErr := j.closeTemporary(f)
	if writeErr != nil || n != len(wire) || syncErr != nil || statErr != nil || closeErr != nil {
		return j.fail()
	}
	if fire("file-close") || fire("before-rename") {
		return j.fail()
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if replacing {
		flags = 0
	}
	if unix.Renameat2(int(j.dir.Fd()), journalPending, int(j.dir.Fd()), name, flags) != nil || fire("after-rename") || j.dir.Sync() != nil || fire("directory-sync") || !j.publicationEvents(name) {
		return j.fail()
	}
	readFD, err := unix.Openat2(int(j.dir.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: below})
	if err != nil {
		return j.fail()
	}
	pin := os.NewFile(uintptr(readFD), "experimental-history-record")
	// Retain immediately, including on every uncertain readback/close path.
	j.uncertain = append(j.uncertain, pin)
	actual, err := journalStat(pin)
	data, readErr := io.ReadAll(io.LimitReader(pin, int64(maxBundleBytes)+1))
	defer clear(data)
	after, afterErr := journalStat(pin)
	if err != nil || readErr != nil || afterErr != nil || actual != after || actual.dev != written.dev || actual.ino != written.ino || actual.mode&unix.S_IFMT != unix.S_IFREG || actual.mode&07777 != 0600 || actual.uid != uint32(os.Geteuid()) || actual.links != 1 || !bytes.Equal(data, wire) {
		return j.fail()
	}
	if b.revision == 2 {
		if err := j.watchFile(pin); err != nil {
			return j.fail()
		}
		j.inflight = ""
	} else {
		j.inflight = name
	}
	j.bytes += len(wire) - len(old.wire)
	j.records[name] = journalObject{file: pin, stamp: actual, wire: bytes.Clone(wire)}
	j.uncertain = j.uncertain[:len(j.uncertain)-1]
	// Enroll the new pin BEFORE retiring the old one. A later failure must not
	// leave a successfully closed old descriptor in the active close roster.
	if replacing && j.closeTemporary(old.file) != nil {
		j.retired = append(j.retired, old)
		return j.fail()
	}
	clear(old.wire)
	j.dirID, err = journalStat(j.dir)
	if err != nil || j.check() != nil {
		return j.fail()
	}
	return nil
}
func (j *historyJournal) close() error {
	if j == nil || j.self != j {
		return ErrInvalid
	}
	if j.closeFailed {
		return ErrReview
	}
	if j.closed {
		return nil
	}
	names := make([]string, 0, len(j.records))
	for name := range j.records {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		r := j.records[name]
		if r.file != nil {
			if j.closeTemporary(r.file) != nil {
				return ErrReview
			}
			r.file = nil
			clear(r.wire)
			j.records[name] = r
		}
	}
	// A readback error may retain a new RO pin even before roster enrollment.
	for _, f := range j.uncertain {
		if j.closeTemporary(f) != nil {
			return ErrReview
		}
	}
	j.uncertain = nil
	if j.watch >= 0 {
		if unix.Close(j.watch) != nil {
			j.closeFailed = true
			return j.fail()
		}
		j.watch = -1
	}
	if j.closeTemporary(j.dir) != nil {
		return ErrReview
	}
	j.closed = true
	return nil
}

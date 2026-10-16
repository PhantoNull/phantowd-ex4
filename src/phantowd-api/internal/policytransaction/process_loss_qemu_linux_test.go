//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

const crashMode = "PHANTOWD_OPERATION_CRASH_CHILD"
const crashStage = "PHANTOWD_OPERATION_CRASH_STAGE"
const crashChallenge = "PHANTOWD_OPERATION_CRASH_CHALLENGE"

var crashStages = []string{"before-intent", "after-intent", "before-policy", "after-policy", "after-readback", "before-receipt", "after-receipt"}
var syscallCrashRoles = []string{"intent", "policy", "receipt"}
var syscallCrashPoints = []string{"partial-write", "full-write", "file-sync", "file-close", "before-rename", "after-rename", "directory-sync"}

type crashGate struct {
	Stage     string `json:"stage"`
	Challenge string `json:"challenge"`
	PID       int    `json:"pid"`
	Root      string `json:"root"`
}

func knownCrashStage(s string) bool {
	for _, stage := range crashStages {
		if s == stage {
			return true
		}
	}
	role, point, ok := strings.Cut(s, "/")
	if ok {
		for _, r := range syscallCrashRoles {
			for _, p := range syscallCrashPoints {
				if role == r && point == p {
					return true
				}
			}
		}
	}
	return false
}
func validChallenge(s string) bool {
	if len(s) != 32 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s && s != strings.Repeat("0", 32)
}
func decodeCrashGate(data []byte, stage, challenge string, pid int) (crashGate, error) {
	if len(data) == 0 || len(data) > 512 || data[len(data)-1] != '\n' || !knownCrashStage(stage) || !validChallenge(challenge) {
		return crashGate{}, ErrInvalid
	}
	if _, e := configjson.DecodeEnvelope(data, 512, 2, "stage", "challenge", "pid", "root"); e != nil {
		return crashGate{}, ErrInvalid
	}
	var g crashGate
	if json.Unmarshal(data, &g) != nil || g.Stage != stage || g.Challenge != challenge || g.PID != pid || pid <= 0 || len(g.Root) > 128 || filepath.Clean(g.Root) != g.Root || filepath.Dir(g.Root) != "/tmp" || !strings.HasPrefix(filepath.Base(g.Root), "phantowd-transaction-") {
		return crashGate{}, ErrInvalid
	}
	return g, nil
}

// Preserve the same bounded buffered reader through child death; otherwise a
// duplicate gate already prefetched by ReadBytes could disappear from the EOF
// check when switching back to the underlying pipe.
func readCrashGate(out io.Reader, stage, challenge string, pid int) (crashGate, *bufio.Reader, error) {
	if out == nil {
		return crashGate{}, nil, ErrInvalid
	}
	reader := bufio.NewReader(io.LimitReader(out, 513))
	line, e := reader.ReadBytes('\n')
	if e != nil {
		return crashGate{}, reader, ErrInvalid
	}
	gate, e := decodeCrashGate(line, stage, challenge, pid)
	return gate, reader, e
}

// This helper exists ONLY in this Go test binary. The normal API has no child
// selector, existing-state opener or subprocess fixture mode for this protocol.
func TestPolicyOperationCrashChild(t *testing.T) {
	if os.Getenv(crashMode) == "" {
		return
	}
	stage, challenge := os.Getenv(crashStage), os.Getenv(crashChallenge)
	if os.Getenv(crashMode) != "1" || !knownCrashStage(stage) || !validChallenge(challenge) {
		t.Fatal("invalid crash child request")
	}
	c, e := naspolicy.Decode(strings.NewReader(testPolicy))
	if e != nil {
		t.Fatal("invalid invented base")
	}
	// Do not defer Close/disposal: the expected exit is actual SIGKILL, not a
	// returned fake error, clean unwind, voluntary exit or timer expiration.
	var w *writer
	gate := func() {
		if w == nil {
			t.Fatal("gate intercepted base construction")
		}
		if json.NewEncoder(os.Stdout).Encode(crashGate{stage, challenge, os.Getpid(), w.path}) != nil {
			t.Fatal("gate emission failed")
		}
		var token [1]byte
		_, _ = io.ReadFull(os.Stdin, token[:])
		t.Fatal("crash gate unexpectedly resumed")
	}
	if role, point, syscallGate := strings.Cut(stage, "/"); syscallGate {
		w, e = newDisposableWithCrash(context.Background(), testInstallation, c, &disposableCrash{role, point, gate})
	} else {
		w, e = newDisposable(context.Background(), testInstallation, c)
		if e == nil {
			w.boundary = func(name string) {
				if name == stage {
					gate()
				}
			}
		}
	}
	if e != nil {
		t.Fatal("fresh child writer unavailable")
	}
	fixtureRevision(&c, 2)
	c.FileServices.Shares.Shares[0].RelativePath = "after-books"
	c.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
	c.FileServices.NFS.Exports[0].RelativePath = "after-books"
	c.ISCSI.Targets[0].State = "enabled" // desired data only; no service exists
	_, _ = w.execute(context.Background(), c)
	t.Fatal("crash writer returned before signal")
}

type crashFile struct {
	f    *os.File
	meta unix.Statx_t
}
type crashRefs struct {
	path     string
	dirs     [3]*os.File
	ids      [3]rootStamp
	dirMeta  [3]unix.Statx_t
	files    [2]crashFile
	names    [2]map[string]unix.Statx_t
	closed   bool
	postLoss bool
}

func crashFileStat(fd int, name string, flags int) (unix.Statx_t, error) {
	var x unix.Statx_t
	const required = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_CTIME | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(fd, name, flags|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &x) != nil || x.Mask&required != required || x.Mnt_id == 0 {
		return x, ErrReview
	}
	return x, nil
}

var crashRoles = [2]struct {
	current, pending string
	limit            int
}{{"nas-services.json", ".nas-services.pending", naspolicy.MaxInputBytes}, {"operation.json", ".operation.pending", maxBundleBytes}}

func crashCensus(dir *os.File, role int) (map[string]unix.Statx_t, error) {
	cursor, e := rootOpen(int(dir.Fd()), ".", below)
	if e != nil {
		return nil, ErrReview
	}
	names, e := cursor.Readdirnames(3)
	complete := errors.Is(e, io.EOF)
	if e == nil && len(names) < 3 {
		more, err := cursor.Readdirnames(1)
		names = append(names, more...)
		complete = errors.Is(err, io.EOF) && len(more) == 0
	}
	if cursor.Close() != nil || !complete || len(names) > 2 {
		return nil, ErrReview
	}
	out := map[string]unix.Statx_t{}
	for _, name := range names {
		if name != crashRoles[role].current && name != crashRoles[role].pending {
			return nil, ErrReview
		}
		x, e := crashFileStat(int(dir.Fd()), name, unix.AT_SYMLINK_NOFOLLOW)
		if e != nil || x.Mode&unix.S_IFMT != unix.S_IFREG || x.Mode&07777 != 0600 || x.Uid != uint32(os.Geteuid()) || x.Nlink != 1 || x.Size > uint64(crashRoles[role].limit) {
			return nil, ErrReview
		}
		if _, duplicate := out[name]; duplicate {
			return nil, ErrReview
		}
		out[name] = x
	}
	return out, nil
}
func captureCrashRefs(path string) (*crashRefs, error) {
	return captureRefsForFilesystem(path, unix.TMPFS_MAGIC)
}

// Test-only shared capture; the separate media fixture validates its fixed
// bounded synthetic ext4 device before requesting that explicit profile.
func captureRefsForFilesystem(path string, filesystem int64) (*crashRefs, error) {
	r := &crashRefs{path: path}
	fail := func() (*crashRefs, error) { return r, ErrReview }
	var e error
	r.dirs[0], e = rootOpen(unix.AT_FDCWD, path, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if e != nil {
		return fail()
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(r.dirs[0].Fd()), &fs) != nil || int64(fs.Type) != filesystem || !rootCensus(r.dirs[0]) {
		return fail()
	}
	for i, name := range []string{"", "policy", "operations"} {
		if i != 0 {
			r.dirs[i], e = rootOpen(int(r.dirs[0].Fd()), name, below)
			if e != nil {
				return fail()
			}
		}
		r.ids[i], e = rootIdentity(r.dirs[i])
		if e != nil {
			return fail()
		}
		r.dirMeta[i], e = crashFileStat(int(r.dirs[i].Fd()), "", unix.AT_EMPTY_PATH)
		if e != nil {
			return fail()
		}
		if i != 0 && (r.ids[i].mount != r.ids[0].mount || r.ids[i].major != r.ids[0].major || r.ids[i].minor != r.ids[0].minor) {
			return fail()
		}
	}
	for i, role := range crashRoles {
		r.names[i], e = crashCensus(r.dirs[i+1], i)
		if e != nil {
			return fail()
		}
		// Pending entries are retained as metadata ONLY, never opened here.
		x, present := r.names[i][role.current]
		if !present {
			continue
		}
		fd, e := unix.Openat2(int(r.dirs[i+1].Fd()), role.current, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: below})
		if e != nil {
			return fail()
		}
		r.files[i].f = os.NewFile(uintptr(fd), "crash-original-observed-file")
		actual, e := crashFileStat(fd, "", unix.AT_EMPTY_PATH)
		if e != nil || actual != x {
			return fail()
		}
		r.files[i].meta = actual
	}
	return r, nil
}
func (r *crashRefs) verify() error {
	if r.closed || r.dirs[0] == nil {
		return ErrReview
	}
	f, e := rootOpen(unix.AT_FDCWD, r.path, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if e != nil {
		return ErrReview
	}
	id, e := rootIdentity(f)
	if f.Close() != nil || e != nil || id != r.ids[0] || !rootCensus(r.dirs[0]) {
		return ErrReview
	}
	for i, dir := range r.dirs {
		if dir == nil {
			return ErrReview
		}
		id, e := rootIdentity(dir)
		if e != nil || id != r.ids[i] {
			return ErrReview
		}
		meta, e := crashFileStat(int(dir.Fd()), "", unix.AT_EMPTY_PATH)
		if e != nil || meta != r.dirMeta[i] {
			return ErrReview
		}
		if i == 0 {
			continue
		}
		witness, e := rootOpen(int(r.dirs[0].Fd()), []string{"policy", "operations"}[i-1], below)
		if e != nil {
			return ErrReview
		}
		id, e = rootIdentity(witness)
		if witness.Close() != nil || e != nil || id != r.ids[i] {
			return ErrReview
		}
		names, e := crashCensus(dir, i-1)
		if e != nil || !reflect.DeepEqual(names, r.names[i-1]) {
			return ErrReview
		}
	}
	for _, file := range r.files {
		if file.f != nil {
			x, e := crashFileStat(int(file.f.Fd()), "", unix.AT_EMPTY_PATH)
			if e != nil || x != file.meta {
				return ErrReview
			}
		}
	}
	return nil
}
func (r *crashRefs) snapshot() ([2][]byte, error) {
	var out [2][]byte
	if r.verify() != nil {
		return out, ErrReview
	}
	for i, file := range r.files {
		if file.f == nil {
			continue
		}
		var e error
		out[i], e = io.ReadAll(io.NewSectionReader(file.f, 0, int64(crashRoles[i].limit)+1))
		if e != nil || len(out[i]) > crashRoles[i].limit || uint64(len(out[i])) != file.meta.Size {
			for _, b := range out {
				clear(b)
			}
			return [2][]byte{}, ErrReview
		}
	}
	if r.verify() != nil {
		for _, b := range out {
			clear(b)
		}
		return [2][]byte{}, ErrReview
	}
	return out, nil
}

type lossDiagnosis struct {
	kind    policyevidence.Kind
	review  bool
	pending bool
}

func (r *crashRefs) observeLoss() (lossDiagnosis, error) {
	if !r.postLoss {
		return lossDiagnosis{}, ErrReview
	}
	snapshot, e := r.snapshot()
	if e != nil {
		return lossDiagnosis{}, ErrReview
	}
	defer func() {
		for _, b := range snapshot {
			clear(b)
		}
	}()
	for i, role := range crashRoles {
		if _, present := r.names[i][role.pending]; present {
			return lossDiagnosis{review: true, pending: true}, nil
		}
	}
	evidence := policyevidence.Evidence{InstallationID: testInstallation, Current: policyevidence.Slot{State: policyevidence.Present, Data: snapshot[0]},
		Intent: policyevidence.Slot{State: policyevidence.Absent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}}
	if snapshot[1] != nil {
		b, e := decodeBundle(bytes.NewReader(snapshot[1]))
		if e != nil {
			return lossDiagnosis{}, ErrReview
		}
		defer b.clear()
		evidence.Intent = policyevidence.Slot{State: policyevidence.Present, Data: b.intent}
		if b.revision == 2 {
			evidence.Receipt = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
		}
	}
	d, e := policyevidence.Match(evidence)
	if e != nil {
		return lossDiagnosis{}, ErrReview
	}
	// Verified process loss requires review even for an empty journal or matching
	// receipt. This test-only value grants no replay/activation/Owner admission.
	return lossDiagnosis{kind: d.Kind(), review: true}, nil
}

// Explicit test-only teardown after verified child death. Retain the acquired
// directory locks until their generated names are removed. No recursive delete,
// raw-FD retry, arbitrary input path or product recovery operation is involved.
func (r *crashRefs) dispose() error {
	if r.closed {
		return ErrReview
	}
	if r.verify() != nil {
		return ErrReview
	}
	for _, file := range r.files {
		if file.f != nil && file.f.Close() != nil {
			return ErrReview
		}
	}
	for i, role := range crashRoles {
		for _, name := range []string{role.current, role.pending} {
			if _, exists := r.names[i][name]; exists && unix.Unlinkat(int(r.dirs[i+1].Fd()), name, 0) != nil {
				return ErrReview
			}
		}
		name := []string{"policy", "operations"}[i]
		if unix.Unlinkat(int(r.dirs[0].Fd()), name, unix.AT_REMOVEDIR) != nil || r.dirs[i+1].Close() != nil {
			return ErrReview
		}
	}
	if os.Remove(r.path) != nil || r.dirs[0].Close() != nil {
		return ErrReview
	}
	r.closed = true
	return nil
}

type boundedCrashErrors struct{ n int }

func (b *boundedCrashErrors) Write(p []byte) (int, error) {
	if len(p) > 4096-b.n {
		return 0, ErrReview
	}
	b.n += len(p)
	return len(p), nil
}

func TestPolicyOperationSIGKILLObservation(t *testing.T) {
	// Refuse/skip unsupported ordinary host kernels before any child/namespace.
	var x unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, "/tmp", unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &x) != nil || x.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		t.Skip("unique mount IDs unavailable; no positive process-loss qualification")
	}
	for _, stage := range crashStages {
		t.Run(stage, func(t *testing.T) { testCrashStage(t, stage) })
	}
}

func TestPolicyOperationSyscallSIGKILLObservation(t *testing.T) {
	var x unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, "/tmp", unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &x) != nil || x.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		t.Skip("unique mount IDs unavailable; no positive syscall-loss qualification")
	}
	for _, role := range syscallCrashRoles {
		for _, point := range syscallCrashPoints {
			stage := role + "/" + point
			t.Run(stage, func(t *testing.T) { testCrashStage(t, stage) })
		}
	}
}

type crashPhase struct {
	policy, journal uint64
	pending         int
	target          uint64
	point           string
}

func expectedCrashPhase(stage string) crashPhase {
	p := crashPhase{policy: 2, journal: 1, pending: -1}
	if role, point, ok := strings.Cut(stage, "/"); ok {
		p.point = point
		p.target = 2
		published := point == "after-rename" || point == "directory-sync"
		switch role {
		case "intent":
			p.policy = 1
			p.journal = 0
			p.target = 1
			if published {
				p.journal = 1
			}
		case "policy":
			p.policy = 1
			if published {
				p.policy = 2
			}
		case "receipt":
			if published {
				p.journal = 2
			}
		}
		if !published {
			p.pending = 1
			if role == "policy" {
				p.pending = 0
			}
		}
		return p
	}
	if stage == "before-intent" || stage == "after-intent" || stage == "before-policy" {
		p.policy = 1
	}
	if stage == "before-intent" {
		p.journal = 0
	}
	if stage == "after-receipt" {
		p.journal = 2
	}
	return p
}
func testCrashStage(t *testing.T, stage string) {
	testCrashStageWithProbe(t, stage, nil)
}

// RuntimeBundleLossStages and RunRuntimeBundleLossFixture are test-binary-only
// bridges for the external collector test package, not product entry points.
func RuntimeBundleLossStages() []string {
	stages := append([]string(nil), crashStages...)
	for _, role := range syscallCrashRoles {
		for _, point := range syscallCrashPoints {
			stages = append(stages, role+"/"+point)
		}
	}
	return stages
}

func RunRuntimeBundleLossFixture(t *testing.T, stage string, probe func(context.Context, string, bool, policyevidence.Kind) error) {
	t.Helper()
	if !knownCrashStage(stage) || probe == nil {
		t.Fatal("invalid runtime observer test profile")
	}
	var x unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, "/tmp", unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &x) != nil || x.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		t.Skip("unique mount IDs unavailable; no positive runtime-reader loss qualification")
	}
	testCrashStageWithProbe(t, stage, probe)
}

func testCrashStageWithProbe(t *testing.T, stage string, probe func(context.Context, string, bool, policyevidence.Kind) error) {
	t.Helper()
	// Initialize Go's pipe poller before measuring persistent runtime descriptors.
	warmReader, warmWriter, e := os.Pipe()
	if e != nil {
		t.Fatal("pipe warmup unavailable")
	}
	if warmReader.Close() != nil || warmWriter.Close() != nil {
		t.Fatal("pipe warmup closure failed")
	}
	beforeFDs, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal("FD baseline unavailable")
	}
	var challenge [16]byte
	if _, e := rand.Read(challenge[:]); e != nil {
		t.Fatal("fixture challenge unavailable")
	}
	nonce := hex.EncodeToString(challenge[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal("test executable unavailable")
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPolicyOperationCrashChild$", "-test.timeout=9s")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOTRACEBACK=none", crashMode + "=1", crashStage + "=" + stage, crashChallenge + "=" + nonce}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	errorsOut := &boundedCrashErrors{}
	cmd.Stderr = errorsOut
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal("stdout pipe failed")
	}
	in, e := cmd.StdinPipe()
	if e != nil {
		_ = out.Close()
		t.Fatal("stdin pipe failed")
	}
	if cmd.Start() != nil {
		_ = in.Close()
		_ = out.Close()
		t.Fatal("child start failed")
	}
	waited := false
	var refs *crashRefs
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		// Cmd.Wait owns closure of StdinPipe after child exit. Keep it open
		// through SIGKILL, then do not retry Close on that already-closed handle.
		// No test cleanup is attempted through incomplete/unverified references.
		if refs != nil {
			if refs.verify() != nil {
				// Incomplete capture permits only reference release, never unlink.
				for _, file := range refs.files {
					if file.f != nil {
						_ = file.f.Close()
					}
				}
				for _, dir := range refs.dirs {
					if dir != nil {
						_ = dir.Close()
					}
				}
				t.Error("incomplete reference capture preserved without disposal")
			} else if refs.dispose() != nil {
				t.Error("original reference teardown refused")
			}
		}
		after, e := os.ReadDir("/proc/self/fd")
		if e != nil || len(after) != len(beforeFDs) {
			t.Error("descriptor count did not return to baseline")
		}
	}()
	gate, gateReader, e := readCrashGate(out, stage, nonce, cmd.Process.Pid)
	if e != nil {
		t.Fatal("gate not bound to original child/stage/challenge")
	}
	refs, e = captureCrashRefs(gate.Root)
	if e != nil {
		t.Fatal("original root/role capture refused")
	}
	// These are separate descriptions, not dup/SCM_RIGHTS aliases of the child.
	// Parent owns no child lock before SIGKILL; all must actually be Busy.
	for _, dir := range refs.dirs {
		if e := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(e, unix.EWOULDBLOCK) {
			t.Fatal("live child lost an original role lock")
		}
	}
	before, e := refs.snapshot()
	if e != nil {
		t.Fatal("frozen child observation refused")
	}
	if d, e := refs.observeLoss(); e != ErrReview || d.review || d.pending || d.kind != "" {
		t.Fatal("post-loss diagnosis admitted before verified death")
	}
	if cmd.Process.Kill() != nil {
		t.Fatal("planned SIGKILL failed")
	}
	trailing, e := io.ReadAll(gateReader)
	if e != nil || len(trailing) != 0 {
		t.Fatal("duplicate/trailing gate proof")
	}
	e = cmd.Wait()
	waited = true
	var exited *exec.ExitError
	if !errors.As(e, &exited) {
		t.Fatal("child did not terminate by signal")
	}
	status, ok := exited.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || ctx.Err() != nil || errorsOut.n != 0 {
		t.Fatal("exit was not the planned live-child SIGKILL")
	}
	if probe != nil {
		phase := expectedCrashPhase(stage)
		kind := policyevidence.PublicationUnconfirmed
		switch {
		case phase.pending >= 0:
			kind = ""
		case phase.journal == 0:
			kind = policyevidence.NoRecordedOperation
		case phase.journal == 2:
			kind = policyevidence.LocalConfirmationObserved
		case phase.policy == 1:
			kind = policyevidence.IntentBaseObserved
		}
		// The runtime reader acquires its own observation locks AFTER verified
		// death and closes before these independent original references lock.
		// Original held/census/statx checks bracket the whole runtime lifetime.
		if refs.verify() != nil || probe(ctx, gate.Root, phase.pending >= 0, kind) != nil || refs.verify() != nil {
			t.Fatal("runtime bundle observer changed or misdiagnosed preserved evidence")
		}
	}
	// Reacquire only read-observation locks on the references held BEFORE loss.
	// This is not uninterrupted writer authority, replay or admission after loss.
	for _, dir := range refs.dirs {
		if unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			t.Fatal("original post-loss lock unavailable")
		}
	}
	refs.postLoss = true
	after, e := refs.snapshot()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("process loss changed captured evidence")
	}
	baseConfig, e := naspolicy.Decode(strings.NewReader(testPolicy))
	if e != nil {
		t.Fatal("base fixture invalid")
	}
	base, _ := json.Marshal(baseConfig)
	current, e := naspolicy.Decode(bytes.NewReader(after[0]))
	if e != nil {
		t.Fatal("current became invalid")
	}
	phase := expectedCrashPhase(stage)
	wantRevision := phase.policy
	if current.Revision != wantRevision {
		t.Fatal("incorrect post-loss policy phase")
	}
	expected := base
	if wantRevision == 2 {
		fixtureRevision(&baseConfig, 2)
		baseConfig.FileServices.Shares.Shares[0].RelativePath = "after-books"
		baseConfig.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
		baseConfig.FileServices.NFS.Exports[0].RelativePath = "after-books"
		baseConfig.ISCSI.Targets[0].State = "enabled"
		expected, _ = json.Marshal(baseConfig)
	}
	if !bytes.Equal(after[0], expected) {
		t.Fatal("actual protocol settings became split or unexpected")
	}
	if phase.journal == 0 {
		if after[1] != nil || !bytes.Equal(after[0], base) {
			t.Fatal("pre-intent evidence changed")
		}
		d, e := refs.observeLoss()
		if e != nil || !d.review || (phase.pending < 0 && (d.kind != policyevidence.NoRecordedOperation || d.pending)) || (phase.pending >= 0 && (!d.pending || d.kind != "")) {
			t.Fatal("empty journal erased process-loss review")
		}
	} else {
		b, e := decodeBundle(bytes.NewReader(after[1]))
		if e != nil {
			t.Fatal("operation evidence invalid")
		}
		defer b.clear()
		if !bytes.Equal(b.base, base) {
			t.Fatal("historical base lost")
		}
		rc := policyevidence.Slot{State: policyevidence.Absent}
		wantKind := policyevidence.PublicationUnconfirmed
		if wantRevision == 1 {
			wantKind = policyevidence.IntentBaseObserved
		}
		if phase.journal == 2 {
			if b.revision != 2 {
				t.Fatal("receipt missing")
			}
			rc = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
			wantKind = policyevidence.LocalConfirmationObserved
		} else if b.revision != 1 {
			t.Fatal("premature confirmation")
		}
		d, e := policyevidence.Match(policyevidence.Evidence{InstallationID: testInstallation, Current: policyevidence.Slot{State: policyevidence.Present, Data: after[0]}, Intent: policyevidence.Slot{State: policyevidence.Present, Data: b.intent}, Receipt: rc})
		if e != nil || d.Kind() != wantKind {
			t.Fatal("incorrect read-only post-loss diagnosis")
		}
		observed, e := refs.observeLoss()
		if e != nil || !observed.review || (phase.pending < 0 && (observed.kind != wantKind || observed.pending)) || (phase.pending >= 0 && (!observed.pending || observed.kind != "")) {
			t.Fatal("post-loss diagnosis cleared review or changed kind")
		}
	}
	// Independent TEST ORACLE only: inspect synthetic staged bytes without atime
	// changes. The post-loss observer above never opens/parses pending contents.
	for i, role := range crashRoles {
		_, present := refs.names[i][role.pending]
		if present != (phase.pending == i) {
			t.Fatal("wrong pending role at syscall boundary")
		}
		if present {
			assertPendingCrashOracle(t, refs, i, phase, base)
		}
	}
	// Never open a writer/Store, fsync, retry or mutate these files to observe
	// them. Repeated observation must preserve bytes AND all captured metadata.
	repeated, e := refs.snapshot()
	if e != nil || !reflect.DeepEqual(after, repeated) {
		t.Fatal("read-only observation changed evidence")
	}
}

func assertPendingCrashOracle(t *testing.T, refs *crashRefs, role int, phase crashPhase, base []byte) {
	t.Helper()
	if refs.verify() != nil {
		t.Fatal("pending oracle identity refused")
	}
	fd, e := unix.Openat2(int(refs.dirs[role+1].Fd()), crashRoles[role].pending, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NOATIME | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: below})
	if e != nil {
		t.Fatal("synthetic pending oracle open failed")
	}
	f := os.NewFile(uintptr(fd), "independent-synthetic-pending-oracle")
	meta, metaErr := crashFileStat(fd, "", unix.AT_EMPTY_PATH)
	if metaErr != nil || meta != refs.names[role][crashRoles[role].pending] {
		_ = f.Close()
		t.Fatal("pending oracle original identity mismatch")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, int64(crashRoles[role].limit)+1))
	closeErr := f.Close()
	defer clear(data)
	if readErr != nil || closeErr != nil || len(data) > crashRoles[role].limit || refs.verify() != nil {
		t.Fatal("pending oracle changed or exceeded evidence")
	}
	if phase.point == "partial-write" {
		if !bytes.Equal(data, []byte(`{"format`)) {
			t.Fatal("partial pending prefix was not exactly eight bytes")
		}
		return
	}
	// Derive independently declared next settings, never adopt staged contents.
	c, e := naspolicy.Decode(bytes.NewReader(base))
	if e != nil {
		t.Fatal("oracle base")
	}
	fixtureRevision(&c, 2)
	c.FileServices.Shares.Shares[0].RelativePath = "after-books"
	c.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
	c.FileServices.NFS.Exports[0].RelativePath = "after-books"
	c.ISCSI.Targets[0].State = "enabled"
	wire, _ := json.Marshal(c)
	if role == 0 {
		if !bytes.Equal(data, wire) {
			t.Fatal("pending policy is split or unexpected")
		}
	} else {
		b, e := decodeBundle(bytes.NewReader(data))
		if e != nil {
			t.Fatal("full staged bundle invalid")
		}
		defer b.clear()
		if b.revision != phase.target || !bytes.Equal(b.base, base) {
			t.Fatal("staged operation lost base/phase")
		}
		rc := policyevidence.Slot{State: policyevidence.Absent}
		want := policyevidence.PublicationUnconfirmed
		if phase.target == 2 {
			rc = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
			want = policyevidence.LocalConfirmationObserved
		}
		d, e := policyevidence.Match(policyevidence.Evidence{InstallationID: testInstallation, Current: policyevidence.Slot{State: policyevidence.Present, Data: wire}, Intent: policyevidence.Slot{State: policyevidence.Present, Data: b.intent}, Receipt: rc})
		if e != nil || d.Kind() != want {
			t.Fatal("staged operation candidate/receipt tuple mismatch")
		}
	}
}

func TestCrashGateStrictBindingAndBounds(t *testing.T) {
	const nonce = "11111111222233334444555555555555"
	g := crashGate{"after-intent", nonce, 123, "/tmp/phantowd-transaction-fixed"}
	data, _ := json.Marshal(g)
	data = append(data, '\n')
	if _, e := decodeCrashGate(data, g.Stage, nonce, 123); e != nil {
		t.Fatal("valid gate refused")
	}
	for _, bad := range [][]byte{nil, []byte("{}\n"), data[:len(data)-1], append(bytes.Clone(data), data...), bytes.Repeat([]byte("x"), 513),
		[]byte(strings.Replace(string(data), `"pid":123`, `"pid":124`, 1)), []byte(strings.Replace(string(data), `"pid":123`, `"pid":123,"pid":123`, 1)),
		[]byte(strings.Replace(string(data), "after-intent", "after-policy", 1)), []byte(strings.Replace(string(data), nonce, strings.Repeat("a", 32), 1)),
		[]byte(strings.Replace(string(data), "/tmp/phantowd-transaction-fixed", "/tmp/../other", 1)),
	} {
		if _, e := decodeCrashGate(bad, g.Stage, nonce, 123); e != ErrInvalid {
			t.Fatal("invalid gate admitted")
		}
	}
}

func TestCrashGateStreamPreservesPrefetchedTail(t *testing.T) {
	const nonce = "11111111222233334444555555555555"
	g := crashGate{"after-intent", nonce, 123, "/tmp/phantowd-transaction-fixed"}
	data, _ := json.Marshal(g)
	data = append(data, '\n')
	for _, suffix := range [][]byte{nil, []byte("x"), data, bytes.Repeat([]byte("x"), 1024)} {
		_, reader, e := readCrashGate(bytes.NewReader(append(bytes.Clone(data), suffix...)), g.Stage, nonce, 123)
		if e != nil {
			t.Fatal("first bounded frame refused")
		}
		tail, e := io.ReadAll(reader)
		if e != nil || (len(tail) == 0) != (len(suffix) == 0) {
			t.Fatal("prefetched trailing proof was discarded")
		}
	}
	if _, _, e := readCrashGate(nil, g.Stage, nonce, 123); e != ErrInvalid {
		t.Fatal("nil stream")
	}
}

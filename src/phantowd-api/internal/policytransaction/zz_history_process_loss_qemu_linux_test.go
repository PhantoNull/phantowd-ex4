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
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

const historyChildMode = "PHANTOWD_HISTORY_CRASH_CHILD"

func RuntimeHistoryLossStages() []string {
	var stages []string
	for _, role := range syscallCrashRoles {
		for _, point := range syscallCrashPoints {
			stages = append(stages, role+"/"+point)
		}
	}
	return stages
}

func TestHistoryOperationCrashChild(t *testing.T) {
	if os.Getenv(historyChildMode) == "" {
		return
	}
	stage, nonce := os.Getenv(crashStage), os.Getenv(crashChallenge)
	medium := disposableTmpfs
	switch os.Getenv(historyChildMode) {
	case "1":
	case "ext4":
		medium = disposableFixedExt4
		requireObserverMedia(t, false)
	default:
		t.Fatal("invalid history child medium")
	}
	if !validChallenge(nonce) {
		t.Fatal("invalid history child")
	}
	role, point, ok := strings.Cut(stage, "/")
	if !ok || !knownCrashStage(stage) {
		t.Fatal("invalid history stage")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal("history invented base")
	}
	var w *writer
	emit := func(name string) {
		if w == nil || json.NewEncoder(os.Stdout).Encode(crashGate{name, nonce, os.Getpid(), w.path}) != nil {
			t.Fatal("history gate emission")
		}
	}
	gate := func() {
		emit(stage)
		var b [1]byte
		_, _ = io.ReadFull(os.Stdin, b[:])
		t.Fatal("history crash gate resumed")
	}
	w, err = newDisposableOnMedium(context.Background(), testInstallation, c, nil, true, &disposableCrash{role, point, gate}, medium)
	if err != nil {
		t.Fatal("history writer construction")
	}
	fixtureRevision(&c, 2)
	if out, err := w.executeHistory(context.Background(), c); err != nil || out.revision != 2 {
		t.Fatal("history first operation")
	}
	// The parent captures the first original BEFORE allowing any second effect.
	emit("after-receipt")
	var token [1]byte
	if _, err := io.ReadFull(os.Stdin, token[:]); err != nil || token[0] != 'N' {
		t.Fatal("history first gate release")
	}
	fixtureRevision(&c, 3)
	c.FileServices.Shares.Shares[0].RelativePath = "after-books"
	c.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
	c.FileServices.NFS.Exports[0].RelativePath = "after-books"
	c.ISCSI.Targets[0].State = "enabled" // desired data, never a target activation
	_, _ = w.executeHistory(context.Background(), c)
	t.Fatal("history writer returned before planned SIGKILL")
}

func firstHistoryStillOriginal(first, latest *crashRefs, before map[string][]byte) bool {
	if first == nil || latest == nil || len(first.extraFiles) != 1 {
		return false
	}
	for i, dir := range first.dirs {
		actual, err := rootIdentity(dir)
		if err != nil {
			return false
		}
		// Only known second-operation child-directory timestamps may advance.
		expected := first.ids[i]
		if i != 0 {
			actual.mtime, actual.ctime = expected.mtime, expected.ctime
		}
		if actual != expected {
			return false
		}
		current := latest.ids[i]
		current.mtime, current.ctime = expected.mtime, expected.ctime
		if current != expected {
			return false
		}
	}
	for name, file := range first.extraFiles {
		meta, err := crashFileStat(int(file.f.Fd()), "", unix.AT_EMPTY_PATH)
		if err != nil || meta != file.meta || latest.extraFiles[name].meta != file.meta {
			return false
		}
		data, err := io.ReadAll(io.NewSectionReader(file.f, 0, int64(maxBundleBytes)+1))
		if err != nil || !bytes.Equal(data, before[name]) {
			return false
		}
	}
	return true
}

// Independent test-only loss context: matching bytes never erase known child
// death. Pending is metadata only; no staged or current data is read here then.
func (r *crashRefs) observeHistoryLoss(checkpoint []byte) (lossDiagnosis, error) {
	if !r.history || !r.postLoss || r.verify() != nil {
		return lossDiagnosis{}, ErrReview
	}
	if _, present := r.names[0][".nas-services.pending"]; present {
		return lossDiagnosis{review: true, pending: true}, nil
	}
	if _, present := r.names[1][journalPending]; present {
		return lossDiagnosis{review: true, pending: true}, nil
	}
	snapshot, err := r.historySnapshot()
	if err != nil {
		return lossDiagnosis{}, ErrReview
	}
	d, err := MatchNamedBundleHistoryObservation(testInstallation, policyevidence.Slot{State: policyevidence.Present, Data: checkpoint},
		policyevidence.Slot{State: policyevidence.Present, Data: snapshot["policy"]}, historySnapshotEntries(snapshot))
	if err != nil {
		return lossDiagnosis{}, ErrReview
	}
	return lossDiagnosis{review: true, kind: d.Kind()}, nil
}

// Test-binary-only bridge: caller supplies the actual read-only runtime probe,
// never a writer/backend. Observation locks are acquired only after verified
// original-child death, and never treated as uninterrupted writer authority.
func RunRuntimeHistoryLossFixture(t *testing.T, stage string, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	runRuntimeHistoryLossFixture(t, stage, probe, disposableTmpfs)
}

// Separate opt-in parent; it never replaces the existing tmpfs loss matrix.
func RunRuntimeHistoryExt4LossFixture(t *testing.T, stage string, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	requireObserverMedia(t, false)
	runRuntimeHistoryLossFixture(t, stage, probe, disposableFixedExt4)
}

func runRuntimeHistoryLossFixture(t *testing.T, stage string, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error, medium disposableMedium) {
	t.Helper()
	parent, filesystem, mediumErr := medium.location()
	valid := false
	for _, s := range RuntimeHistoryLossStages() {
		valid = valid || s == stage
	}
	if !valid || probe == nil || mediumErr != nil {
		t.Fatal("invalid history loss profile")
	}
	var x unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, parent, unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &x) != nil || x.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		t.Skip("unique mount IDs unavailable; no history process-loss qualification")
	}
	r, w, err := os.Pipe()
	if err != nil || r.Close() != nil || w.Close() != nil {
		t.Fatal("history poller warmup")
	}
	baseline, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("history FD baseline")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("history nonce")
	}
	challenge := hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("history executable")
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHistoryOperationCrashChild$", "-test.timeout=9s")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOTRACEBACK=none", historyChildMode + "=1", crashStage + "=" + stage, crashChallenge + "=" + challenge}
	if medium == disposableFixedExt4 {
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOTRACEBACK=none", "TMPDIR=" + historyExt4Root, historyChildMode + "=ext4", crashStage + "=" + stage, crashChallenge + "=" + challenge}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stderr := &boundedCrashErrors{}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("history stdout pipe")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		_ = out.Close()
		t.Fatal("history stdin pipe")
	}
	if cmd.Start() != nil {
		_ = in.Close()
		_ = out.Close()
		t.Fatal("history child start")
	}
	waited, dead := false, false
	var first, latest *crashRefs
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		// Cmd.Wait owns pipe closure; never close those descriptors again.
		if first != nil && first.releaseReferences() != nil {
			t.Error("history first-reference closure")
		}
		if latest != nil {
			if dead && latest.verify() == nil {
				for _, dir := range latest.dirs {
					if unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
						t.Error("history cleanup lock")
						return
					}
				}
				if latest.dispose() != nil {
					t.Error("history known-name disposal")
				}
			} else {
				if latest.releaseReferences() != nil {
					t.Error("history incomplete reference closure")
				}
				t.Error("history evidence preserved without unlink")
			}
		}
		end, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(end) != len(baseline) {
			t.Error("history descriptor baseline changed")
		}
	}()
	// One original bounded buffered reader retains both gates AND prefetched tail.
	reader := bufio.NewReader(io.LimitReader(out, 1027))
	readGate := func(expected string) crashGate {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal("history gate unavailable")
		}
		g, err := decodeHistoryLossGate(line, expected, challenge, cmd.Process.Pid, medium)
		if err != nil {
			t.Fatal("history gate identity/challenge/stage")
		}
		return g
	}
	g := readGate("after-receipt")
	first, err = captureRefsProfile(g.Root, filesystem, true)
	if err != nil {
		t.Fatal("history first capture")
	}
	for _, dir := range first.dirs {
		if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatal("history first lock absent")
		}
	}
	before, err := first.historySnapshot()
	if err != nil || len(first.extraFiles) != 1 {
		t.Fatal("history first snapshot")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal("history oracle checkpoint")
	}
	checkpoint, _ := json.Marshal(c)
	fixtureRevision(&c, 2)
	policy2, _ := json.Marshal(c)
	if !bytes.Equal(before["policy"], policy2) {
		t.Fatal("history first policy not confirmed expectation")
	}
	firstEntries := historySnapshotEntries(before)
	d, err := MatchNamedBundleHistoryObservation(testInstallation, policyevidence.Slot{State: policyevidence.Present, Data: checkpoint}, policyevidence.Slot{State: policyevidence.Present, Data: policy2}, firstEntries)
	if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
		t.Fatal("history first operation coherence")
	}
	if medium == disposableFixedExt4 {
		// This is the known mutable policy slot, NOT the confirmed first history
		// record or any directory/lock. Its exact revision2 bytes were verified
		// above. Keeping an obsolete unlinked policy read pin after revision3's
		// rename makes Linux refuse RO remount (even though the pin is O_RDONLY).
		// Release only this temporary capture BEFORE authorizing second effects;
		// all original confirmed-record and directory references remain held.
		policyPin := first.files[0].f
		first.files[0].f = nil // Never retry Close on this capture after uncertainty.
		if policyPin == nil || policyPin.Close() != nil {
			t.Fatal("history mutable-policy capture close")
		}
	}
	if n, err := in.Write([]byte{'N'}); n != 1 || err != nil {
		t.Fatal("history first gate acknowledgement")
	}
	g2 := readGate(stage)
	if g2.Root != g.Root {
		t.Fatal("history target root switched")
	}
	latest, err = captureRefsProfile(g.Root, filesystem, true)
	if err != nil || !firstHistoryStillOriginal(first, latest, before) {
		t.Fatal("history first original lost before kill")
	}
	for _, dir := range latest.dirs {
		if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatal("history second lock absent")
		}
	}
	frozen, err := latest.historySnapshot()
	if err != nil {
		t.Fatal("history target snapshot")
	}
	if d, err := latest.observeHistoryLoss(checkpoint); err != ErrReview || d != (lossDiagnosis{}) {
		t.Fatal("history loss diagnosis before verified death")
	}
	if cmd.Process.Kill() != nil {
		t.Fatal("history planned kill")
	}
	tail, err := io.ReadAll(reader)
	if err != nil || len(tail) != 0 {
		t.Fatal("history duplicate/trailing proof")
	}
	err = cmd.Wait()
	waited = true
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		t.Fatal("history child not signaled")
	}
	status, ok := exited.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || ctx.Err() != nil || stderr.n != 0 {
		t.Fatal("history exit was not planned live SIGKILL")
	}
	dead = true
	phase := expectedCrashPhase(stage)
	fixtureRevision(&c, 3)
	c.FileServices.Shares.Shares[0].RelativePath, c.FileServices.Shares.Shares[0].Grants[0].Access = "after-books", "ro"
	c.FileServices.NFS.Exports[0].RelativePath, c.ISCSI.Targets[0].State = "after-books", "enabled"
	policy3, _ := json.Marshal(c)
	wantPolicy := policy2
	if phase.policy == 2 {
		wantPolicy = policy3
	}
	if !bytes.Equal(frozen["policy"], wantPolicy) {
		t.Fatal("history protocol policy phase split")
	}
	wantRecords := 2
	if phase.journal == 0 {
		wantRecords = 1
	}
	if len(latest.extraFiles) != wantRecords {
		t.Fatal("history operation set changed")
	}
	wantKind := policyevidence.PublicationUnconfirmed
	if phase.journal == 2 {
		wantKind = policyevidence.LocalConfirmationObserved
	} else if phase.policy == 1 {
		wantKind = policyevidence.IntentBaseObserved
	}
	pending := phase.pending >= 0
	for role, names := range latest.names {
		name := crashRoles[role].pending
		if role == 1 {
			name = journalPending
		}
		_, present := names[name]
		if present != (role == phase.pending) {
			t.Fatal("history wrong pending role")
		}
	}
	if pending {
		wantKind = ""
	}
	if latest.verify() != nil || !firstHistoryStillOriginal(first, latest, before) {
		t.Fatal("history original evidence changed after loss")
	}
	if medium == disposableFixedExt4 {
		// Clean same-kernel remount after verified process death, NOT power loss
		// or reboot. Actual runtime observation must work without write access.
		if err := unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, ""); err != nil {
			t.Fatal("history loss read-only remount", err)
		}
		defer func() {
			if unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|observerMediaRestrictions, "") != nil {
				t.Error("history loss media restoration")
			}
		}()
		requireObserverMedia(t, true)
	}
	if err := probe(ctx, g.Root, bytes.Clone(checkpoint), pending, wantKind); err != nil {
		t.Fatal("history actual runtime observer", err)
	}
	if latest.verify() != nil || !firstHistoryStillOriginal(first, latest, before) {
		t.Fatal("history runtime reader changed original evidence")
	}
	after, err := latest.historySnapshot()
	if err != nil || !reflect.DeepEqual(frozen, after) {
		t.Fatal("history observation changed evidence")
	}
	for _, dir := range latest.dirs {
		if unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			t.Fatal("history original observation lock unavailable")
		}
	}
	latest.postLoss = true
	for range 2 {
		d, err := latest.observeHistoryLoss(checkpoint)
		if err != nil || !d.review || d.pending != pending || d.kind != wantKind {
			t.Fatal("history loss context was cleared or misdiagnosed", err)
		}
	}
	// Every case is known process loss: matching local receipt still grants no
	// writer/retry/activation. No writer/Store is ever opened for adoption here.
}

func historySnapshotEntries(snapshot map[string][]byte) []NamedBundleObservation {
	var entries []NamedBundleObservation
	for name, data := range snapshot {
		if name != "policy" {
			entries = append(entries, NamedBundleObservation{Name: name, Operation: policyevidence.Slot{State: policyevidence.Present, Data: data}})
		}
	}
	return entries
}

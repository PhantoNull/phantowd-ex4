//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

const historyMediaMode = "PHANTOWD_HISTORY_MEDIA_MODE"
const historyMediaRootEnv = "PHANTOWD_HISTORY_MEDIA_ROOT"

func validHistoryMediaRoot(root string) bool {
	if len(root) > 128 || filepath.Clean(root) != root || filepath.Dir(root) != historyExt4Root {
		return false
	}
	base := filepath.Base(root)
	const prefix = "phantowd-transaction-"
	if !strings.HasPrefix(base, prefix) || len(base) <= len(prefix) || len(base) > len(prefix)+32 {
		return false
	}
	for _, ch := range base[len(prefix):] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func decodeHistoryMediaProof(data []byte, stage, nonce string, pid int, root string) (crashGate, error) {
	if len(data) == 0 || len(data) > 512 || data[len(data)-1] != '\n' || !validChallenge(nonce) || pid <= 0 || stage != "producer-closed" && stage != "reader-closed" {
		return crashGate{}, ErrInvalid
	}
	if _, err := configjson.DecodeEnvelope(data, 512, 2, "stage", "challenge", "pid", "root"); err != nil {
		return crashGate{}, ErrInvalid
	}
	var g crashGate
	if json.Unmarshal(data, &g) != nil || g.Stage != stage || g.Challenge != nonce || g.PID != pid || !validHistoryMediaRoot(g.Root) || root != "" && g.Root != root {
		return crashGate{}, ErrInvalid
	}
	return g, nil
}

func TestHistoryMediaProofRejectsForeignOrUnboundedInputs(t *testing.T) {
	const nonce = "11111111222233334444555555555555"
	g := crashGate{"producer-closed", nonce, 123, historyExt4Root + "/phantowd-transaction-fixed"}
	wire, _ := json.Marshal(g)
	wire = append(wire, '\n')
	if _, err := decodeHistoryMediaProof(wire, g.Stage, nonce, 123, ""); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, wire[:len(wire)-1], append(bytes.Clone(wire), wire...), bytes.Repeat([]byte("x"), 513),
		[]byte(strings.Replace(string(wire), `"pid":123`, `"pid":124`, 1)),
		[]byte(strings.Replace(string(wire), `"pid":123`, `"pid":123,"pid":123`, 1)),
		[]byte(strings.Replace(string(wire), historyExt4Root, "/tmp", 1)),
		[]byte(strings.Replace(string(wire), "producer-closed", "reader-closed", 1)),
		[]byte(strings.Replace(string(wire), nonce, strings.Repeat("a", 32), 1))} {
		if _, err := decodeHistoryMediaProof(data, g.Stage, nonce, 123, ""); err != ErrInvalid {
			t.Fatal("invalid media proof admitted")
		}
	}
	if _, err := decodeHistoryMediaProof(wire, g.Stage, nonce, 123, historyExt4Root+"/phantowd-transaction-other"); err != ErrInvalid {
		t.Fatal("foreign root rebound")
	}
}

func TestHistoryMediaProducerChild(t *testing.T) {
	if os.Getenv(historyMediaMode) == "" {
		return
	}
	if os.Getenv(historyMediaMode) != "produce" || !validChallenge(os.Getenv(crashChallenge)) {
		t.Fatal("invalid media producer child")
	}
	requireObserverMedia(t, false)
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := newDisposableHistoryOnExt4(ctx, testInstallation, c)
	if err != nil {
		t.Fatal("media producer construction", err)
	}
	defer w.close() // no disposal; parent observes only after verified clean exit
	for _, n := range []uint64{2, 3} {
		fixtureRevision(&c, n)
		if out, err := w.executeHistory(ctx, c); err != nil || out.revision != n {
			t.Fatal("media producer publication", err)
		}
	}
	if w.close() != nil {
		t.Fatal("media producer closure")
	}
	if json.NewEncoder(os.Stdout).Encode(crashGate{"producer-closed", os.Getenv(crashChallenge), os.Getpid(), w.path}) != nil {
		t.Fatal("media producer proof")
	}
}

// Test-binary-only reader bridge. Neither the normal API binary nor an HTTP
// request has this child selector, caller root path or existing-state writer.
func RunHistoryMediaObservationChild(t *testing.T, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	if os.Getenv(historyMediaMode) == "" {
		return
	}
	root, nonce := os.Getenv(historyMediaRootEnv), os.Getenv(crashChallenge)
	if os.Getenv(historyMediaMode) != "read" || !validHistoryMediaRoot(root) || !validChallenge(nonce) || probe == nil {
		t.Fatal("invalid media observer child")
	}
	requireObserverMedia(t, true)
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, _ := json.Marshal(c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx, root, checkpoint, false, policyevidence.LocalConfirmationObserved); err != nil {
		t.Fatal("new-process media observer", err)
	}
	if json.NewEncoder(os.Stdout).Encode(crashGate{"reader-closed", nonce, os.Getpid(), root}) != nil {
		t.Fatal("media reader proof")
	}
}

func runHistoryMediaChild(t *testing.T, mode, root string) string {
	t.Helper()
	if mode != "produce" && mode != "read" {
		t.Fatal("closed media child mode")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("media child challenge")
	}
	challenge := hex.EncodeToString(nonce[:])
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("media child executable")
	}
	name, stage := "TestHistoryMediaProducerChild", "producer-closed"
	if mode == "read" {
		name, stage = "TestHistoryMediaObservationChild", "reader-closed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+name+"$", "-test.timeout=5s", "-test.count=1")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOTRACEBACK=none", "TMPDIR=" + observerMediaRoot, historyMediaMode + "=" + mode, historyMediaRootEnv + "=" + root, crashChallenge + "=" + challenge}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	errorsOut := &boundedCrashErrors{}
	cmd.Stderr = errorsOut
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("media child pipe")
	}
	if cmd.Start() != nil {
		_ = pipe.Close()
		t.Fatal("media child start")
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	data, readErr := io.ReadAll(io.LimitReader(pipe, 1024))
	err = cmd.Wait()
	waited = true
	if err != nil || readErr != nil || ctx.Err() != nil || errorsOut.n != 0 || cmd.ProcessState == nil || !cmd.ProcessState.Success() || !bytes.HasSuffix(data, []byte("PASS\n")) {
		t.Fatal("media child did not complete cleanly", err)
	}
	frame := bytes.TrimSuffix(data, []byte("PASS\n"))
	g, err := decodeHistoryMediaProof(frame, stage, challenge, cmd.Process.Pid, root)
	if err != nil {
		t.Fatal("media child proof refused")
	}
	return g.Root
}

func historyMediaProcessBoundary(t *testing.T, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	requireObserverMedia(t, false)
	r, w, err := os.Pipe()
	if err != nil || r.Close() != nil || w.Close() != nil {
		t.Fatal("media process poller warmup")
	}
	baseline, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("media process baseline")
	}
	root := runHistoryMediaChild(t, "produce", "")
	refs, err := captureRefsProfile(root, unix.EXT4_SUPER_MAGIC, true)
	if err != nil {
		if refs != nil {
			_ = refs.releaseReferences()
		}
		t.Fatal("media process original references")
	}
	defer func() {
		for _, dir := range refs.dirs {
			if unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
				t.Error("media process cleanup lock")
				return
			}
		}
		if refs.dispose() != nil {
			t.Error("media process known-name disposal")
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(after) != len(baseline) {
			t.Error("media process descriptor baseline changed")
		}
	}()
	before, err := refs.historySnapshot()
	if err != nil || len(refs.extraFiles) != 2 {
		t.Fatal("media process two operations unavailable")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, _ := json.Marshal(c)
	fixtureRevision(&c, 3)
	expected, _ := json.Marshal(c)
	if !bytes.Equal(before["policy"], expected) {
		t.Fatal("media producer settings differ")
	}
	if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, "") != nil {
		t.Fatal("media process read-only remount")
	}
	defer func() {
		if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|observerMediaRestrictions, "") != nil {
			t.Error("media process mount restoration")
		}
	}()
	requireObserverMedia(t, true)
	if runHistoryMediaChild(t, "read", root) != root {
		t.Fatal("reader process rebound root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if probe(ctx, root, checkpoint, false, policyevidence.LocalConfirmationObserved) != nil || refs.verify() != nil {
		t.Fatal("media process independent observation")
	}
	after, err := refs.historySnapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("media process changed original data or metadata")
	}
}

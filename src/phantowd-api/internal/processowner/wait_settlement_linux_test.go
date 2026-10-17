//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/testclosefault"
)

// A real owned process/group with a controlled system-I/O completion boundary.
// The test launcher is fixed to this test executable, never a product backend
// or executable/root/privilege admission. No kernel delay or sleep is injected.
func TestFailedStartWaitSettlementPreservesReview(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	if runtime.GOARCH == "arm" {
		if _, err := testclosefault.Executable(); err != nil {
			t.Skip("requires the guarded disposable code-owner guest")
		}
	}
	owner := New()
	stream := &heldWaitWriter{entered: make(chan struct{}), release: make(chan struct{}), target: newDiagnosticRing()}
	var original *managedProcess
	t.Cleanup(func() {
		stream.releaseOnce.Do(func() { close(stream.release) })
		if original == nil {
			return
		}
		if !original.stopAttempted {
			_ = stopProcess(original) // At most the first stop of this exact group.
		}
		select {
		case <-original.done:
		case <-time.After(forcedWait):
			t.Error("fixture original Wait did not settle during cleanup")
			return
		}
		if err := syscall.Kill(-original.pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Error("fixture original group remains or is uncertain", err)
		}
	})
	owner.launch = func(spec Spec) (*managedProcess, error) {
		if original != nil || spec.Executable != os.Args[0] || spec.RunAs != nil {
			t.Fatal("invalid or repeated fixed fixture launch")
		}
		command := exec.Command(spec.Executable, spec.Args...)
		command.Dir = "/"
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Stdout, command.Stderr = stream, stream.target
		command.WaitDelay = time.Second // Same fixed drain bound as the launcher.
		if err := command.Start(); err != nil {
			return nil, err
		}
		original = &managedProcess{command: command, pid: command.Process.Pid, done: make(chan struct{}),
			stopTimeout: spec.StopTimeout, diagnostics: stream.target}
		go original.wait()
		// Preparation is separately bounded: the child's notice is emitted AFTER
		// installing its SIGTERM disposition. Do not guess this from elapsed time.
		select {
		case <-stream.entered:
		case <-time.After(forcedWait):
			t.Fatal("fixture child did not reach the controlled output boundary")
		}
		return original, nil
	}
	started, err := owner.Start(context.Background(), Spec{
		Executable: os.Args[0], Args: []string{"-test.run=^TestFailedStartWaitSettlementPreservesReview$", "--", "ignore-term"},
		Ready:        func(context.Context) (bool, error) { return false, nil },
		ReadyTimeout: 100 * time.Millisecond, ProbeInterval: 10 * time.Millisecond, StopTimeout: 50 * time.Millisecond,
	})
	if !errors.Is(err, ErrReviewRequired) || !errors.Is(err, ErrNotReady) ||
		started.State != StateReviewRequired || started.Generation != 0 || original == nil || started.PID != original.pid {
		t.Fatal("failed start did not retain original uncertain ownership", started, err)
	}
	if err := syscall.Kill(-started.PID, 0); !errors.Is(err, syscall.ESRCH) || original.exited() {
		t.Fatal("fixture did not distinguish kernel-group absence from Wait completion", err)
	}
	stopped, err := owner.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired || stopped.Generation != 0 ||
		stopped.PID != started.PID || owner.current != original || original.exited() {
		t.Fatalf("pending Wait released or replaced original uncertain ownership: snapshot=%+v err=%v", stopped, err)
	}
	if _, err := owner.Start(context.Background(), Spec{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("pending original Wait allowed a new launch", err)
	}
	stream.releaseOnce.Do(func() { close(stream.release) })
	requireTestOriginalWaitSettled(t, original)
	for range 2 {
		stopped, err := owner.Stop(context.Background())
		if !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired || stopped.Generation != 0 || stopped.PID != 0 {
			t.Fatalf("confirmed original settlement cleared review or retained PID: snapshot=%+v err=%v", stopped, err)
		}
	}
	if _, err := owner.Start(context.Background(), Spec{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("settled failed start allowed automatic restart", err)
	}
}

// An uncertain product stop is NOT a completed Wait notification. Fixtures
// explicitly observe the original notification and group absence before they
// demand PID release. This separate2s test-only observation phase sends no
// signals, retries no stop and never changes any product/worker timeout.
func requireTestOriginalWaitSettled(t *testing.T, original *managedProcess) {
	t.Helper()
	if original == nil || original.pid <= 1 || !original.stopAttempted {
		t.Fatal("settlement requires the original previously stopped process")
	}
	timer := time.NewTimer(forcedWait)
	defer timer.Stop()
	select {
	case <-original.done:
	case <-timer.C:
		t.Fatal("original process Wait did not complete within fixture observation bound")
	}
	if err := syscall.Kill(-original.pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("original Wait completed but the process group remains or is uncertain", err)
	}
}

type heldWaitWriter struct {
	entered, release chan struct{}
	enterOnce        sync.Once
	releaseOnce      sync.Once
	target           *diagnosticRing
}

func (w *heldWaitWriter) Write(data []byte) (int, error) {
	w.enterOnce.Do(func() { close(w.entered) })
	<-w.release
	return w.target.Write(data)
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOwnedForegroundProcessStartsOnlyAfterReadinessAndStopsItsGroup(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}

	owner := New()
	ctx := context.Background()
	readyAfter := time.Now().Add(80 * time.Millisecond)
	probedBeforeReady := false
	started, err := owner.Start(ctx, Spec{
		Executable: os.Args[0],
		Args:       []string{"-test.run=^TestOwnedForegroundProcessStartsOnlyAfterReadinessAndStopsItsGroup$", "--", "wait"},
		Ready: func(context.Context) (bool, error) {
			if time.Now().Before(readyAfter) {
				probedBeforeReady = true
				return false, nil
			}
			return true, nil
		},
		ReadyTimeout:  2 * time.Second,
		ProbeInterval: 10 * time.Millisecond,
		StopTimeout:   time.Second,
	})
	if err != nil {
		t.Fatal("start owned child:", err)
	}
	if started.State != StateReady || started.Generation != 1 || started.PID <= 0 {
		t.Fatalf("readiness was not reflected in the owner state: %+v", started)
	}
	observed, err := owner.Observe(ctx)
	if err != nil || observed.State != StateReady || observed.Generation != started.Generation || observed.PID != started.PID {
		t.Fatalf("live process observation changed or lost owner state: before=%+v after=%+v err=%v", started, observed, err)
	}
	if !probedBeforeReady || time.Now().Before(readyAfter) {
		t.Fatal("owner reported readiness before the probe accepted the service")
	}
	stopped, err := owner.Stop(ctx)
	if err != nil {
		t.Fatal("stop owned child:", err)
	}
	if stopped.State != StateStopped || stopped.PID != 0 || stopped.Generation != 1 {
		t.Fatalf("owned child did not reach a stopped state: %+v", stopped)
	}
}

func TestUnexpectedExitObservedAfterReadinessRequiresReview(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}

	owner := New()
	readyPath := filepath.Join(t.TempDir(), "ready")
	releasePath := filepath.Join(t.TempDir(), "release")
	exitedPath := filepath.Join(t.TempDir(), "exited")
	started, err := owner.Start(context.Background(), Spec{
		Executable: os.Args[0],
		Args: []string{"-test.run=^TestUnexpectedExitObservedAfterReadinessRequiresReview$", "--", "ready-exit",
			readyPath, releasePath, exitedPath},
		Ready: func(context.Context) (bool, error) {
			_, err := os.Stat(readyPath)
			return err == nil, nil
		},
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	})
	if err != nil || started.State != StateReady || started.Generation != 1 {
		t.Fatalf("candidate did not start before the controlled exit: snapshot=%+v err=%v", started, err)
	}
	if err := os.WriteFile(releasePath, []byte("exit"), 0600); err != nil {
		t.Fatal("release child process:", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(exitedPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child process did not reach its controlled exit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		observed, err := owner.Observe(context.Background())
		if errors.Is(err, ErrReviewRequired) {
			if observed.State != StateReviewRequired || observed.Generation != 1 {
				t.Fatalf("unexpected exit did not retain the last generation in review: %+v", observed)
			}
			break
		}
		if err != nil {
			t.Fatalf("observe process after controlled exit: %v", err)
		}
		if observed.Generation != started.Generation || observed.State != StateReady {
			t.Fatalf("owner changed generation without confirmation: %+v", observed)
		}
		if time.Now().After(deadline) {
			t.Fatal("owner did not detect the exited service")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := owner.Start(context.Background(), Spec{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("owner restarted after an observed unexpected exit: %v", err)
	}
}

func TestOwnerRejectsSymlinkExecutableWithoutStartingAnything(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	target, err := os.Executable()
	if err != nil {
		t.Fatal("locate test executable:", err)
	}
	link := t.TempDir() + "/service"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("create test symlink:", err)
	}
	owner := New()
	started, err := owner.Start(context.Background(), Spec{
		Executable: link, Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrInvalid) || started.State != StateStopped || started.PID != 0 {
		t.Fatalf("owner followed an executable symlink or reported a child: snapshot=%+v err=%v", started, err)
	}
}

func TestReadinessTimeoutStopsCandidateWithoutAdvancingGeneration(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	started, err := owner.Start(context.Background(), Spec{
		Executable:   os.Args[0],
		Args:         []string{"-test.run=^TestReadinessTimeoutStopsCandidateWithoutAdvancingGeneration$", "--", "wait"},
		Ready:        func(context.Context) (bool, error) { return false, nil },
		ReadyTimeout: 80 * time.Millisecond, ProbeInterval: 10 * time.Millisecond,
		StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrNotReady) || started.State != StateStopped || started.Generation != 0 || started.PID != 0 {
		t.Fatalf("unready candidate was retained or advanced the generation: snapshot=%+v err=%v", started, err)
	}
}

func TestStopCompletesBoundedCleanupEvenIfCallerContextWasCanceled(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	_, err := owner.Start(context.Background(), Spec{
		Executable:   os.Args[0],
		Args:         []string{"-test.run=^TestStopCompletesBoundedCleanupEvenIfCallerContextWasCanceled$", "--", "wait"},
		Ready:        func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("start candidate:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, err := owner.Stop(ctx)
	if err != nil || stopped.State != StateStopped || stopped.Generation != 1 {
		t.Fatalf("canceled caller prevented bounded child cleanup: snapshot=%+v err=%v", stopped, err)
	}
}

func TestUnexpectedExitRequiresReviewAndBlocksRestart(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	_, err := owner.Start(context.Background(), Spec{
		Executable:   os.Args[0],
		Args:         []string{"-test.run=^TestUnexpectedExitRequiresReviewAndBlocksRestart$", "--", "exit-after"},
		Ready:        func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("start candidate:", err)
	}
	time.Sleep(150 * time.Millisecond)
	stopped, err := owner.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired || stopped.Generation != 1 {
		t.Fatalf("unexpected service exit was reported as clean: snapshot=%+v err=%v", stopped, err)
	}
	if _, err := owner.Start(context.Background(), Spec{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("owner restarted after an uncertain exit: %v", err)
	}
}

func TestForcedTerminationCleansChildButRequiresReview(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	_, err := owner.Start(context.Background(), Spec{
		Executable: os.Args[0],
		Args:       []string{"-test.run=^TestForcedTerminationCleansChildButRequiresReview$", "--", "ignore-term"},
		Ready: func(context.Context) (bool, error) {
			return strings.Contains(string(owner.Diagnostics()), "PROCESS_OWNER_CHILD_IGNORES_TERM"), nil
		},
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond,
		StopTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal("start candidate:", err)
	}
	stopped, err := owner.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired || stopped.Generation != 1 {
		t.Fatalf("forced service termination was reported as a clean stop: snapshot=%+v err=%v", stopped, err)
	}
	if _, err := owner.Start(context.Background(), Spec{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("owner restarted after forced termination: %v", err)
	}
}

func TestReadinessFailureRetainsOnlyBoundedPrivateDiagnostics(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	started, err := owner.Start(context.Background(), Spec{
		Executable:   os.Args[0],
		Args:         []string{"-test.run=^TestReadinessFailureRetainsOnlyBoundedPrivateDiagnostics$", "--", "noisy"},
		Ready:        func(context.Context) (bool, error) { return false, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	})
	if !errors.Is(err, ErrNotReady) || started.State != StateStopped {
		t.Fatalf("unready noisy child was not stopped: snapshot=%+v err=%v", started, err)
	}
	diagnostics := owner.Diagnostics()
	if len(diagnostics) == 0 || len(diagnostics) > maxDiagnostics ||
		started.DiagnosticBytes > maxDiagnostics || !started.DiagnosticsTruncated {
		t.Fatalf("diagnostics were not bounded and marked truncated: bytes=%d snapshot=%+v", len(diagnostics), started)
	}
}

func TestConcurrentLifecycleRequestFailsFastWhileReadinessIsInProgress(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	owner := New()
	readyCalled := make(chan struct{})
	releaseReady := make(chan struct{})
	var once sync.Once
	result := make(chan error, 1)
	go func() {
		_, err := owner.Start(context.Background(), Spec{
			Executable: os.Args[0],
			Args:       []string{"-test.run=^TestConcurrentLifecycleRequestFailsFastWhileReadinessIsInProgress$", "--", "wait"},
			Ready: func(ctx context.Context) (bool, error) {
				once.Do(func() { close(readyCalled) })
				select {
				case <-releaseReady:
					return true, nil
				case <-ctx.Done():
					return false, ctx.Err()
				}
			},
			ReadyTimeout: 2 * time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
		})
		result <- err
	}()
	select {
	case <-readyCalled:
	case <-time.After(time.Second):
		t.Fatal("start did not reach its readiness probe")
	}
	if _, err := owner.Stop(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent stop queued behind an in-progress owner transition: %v", err)
	}
	close(releaseReady)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("start after releasing readiness:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("start did not finish after readiness was released")
	}
	if _, err := owner.Stop(context.Background()); err != nil {
		t.Fatal("stop after readiness:", err)
	}
}

func processOwnerChildMode(args []string) (string, bool) {
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func processOwnerChildArguments(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			if i+2 < len(args) {
				return args[i+2:]
			}
			return nil
		}
	}
	return nil
}

func runProcessOwnerChild(t *testing.T, mode string) {
	switch mode {
	case "ready-exit":
		paths := processOwnerChildArguments(os.Args)
		if len(paths) != 3 {
			t.Fatalf("controlled exit requires three marker paths, got %d", len(paths))
		}
		if err := os.WriteFile(paths[0], []byte("ready"), 0600); err != nil {
			t.Fatal("write readiness marker:", err)
		}
		for {
			if _, err := os.Stat(paths[1]); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := os.WriteFile(paths[2], []byte("exiting"), 0600); err != nil {
			t.Fatal("write exit marker:", err)
		}
	case "wait":
		time.Sleep(time.Minute)
	case "exit":
		return
	case "exit-after":
		time.Sleep(100 * time.Millisecond)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		_, _ = fmt.Fprintln(os.Stdout, "PROCESS_OWNER_CHILD_IGNORES_TERM")
		time.Sleep(time.Minute)
	case "noisy":
		_, _ = strings.NewReader(strings.Repeat("diagnostic-", 20000)).WriteTo(os.Stdout)
		time.Sleep(time.Minute)
	default:
		t.Fatalf("unknown process-owner child mode %q", mode)
	}
}

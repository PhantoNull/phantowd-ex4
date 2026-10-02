//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxReadyTimeout = 30 * time.Second
	maxProbePeriod  = time.Second
	maxStopTimeout  = 15 * time.Second
	forcedWait      = 2 * time.Second
	probeWait       = 20 * time.Millisecond
	maxDiagnostics  = 32 << 10
)

type managedProcess struct {
	command       *exec.Cmd
	pid           int
	done          chan struct{}
	waitErr       error
	waitMu        sync.Mutex
	ready         bool
	stopTimeout   time.Duration
	stopAttempted bool
	diagnostics   *diagnosticRing
}

func (p *managedProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *managedProcess) wait() {
	err := p.command.Wait()
	p.waitMu.Lock()
	p.waitErr = err
	p.waitMu.Unlock()
	close(p.done)
}

type diagnosticRing struct {
	mu      sync.Mutex
	data    []byte
	start   int
	length  int
	dropped uint64
}

func newDiagnosticRing() *diagnosticRing {
	return &diagnosticRing{data: make([]byte, maxDiagnostics)}
}

func (b *diagnosticRing) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(value) >= len(b.data) {
		b.dropped += uint64(b.length + len(value) - len(b.data))
		copy(b.data, value[len(value)-len(b.data):])
		b.start, b.length = 0, len(b.data)
		return len(value), nil
	}
	needed := b.length + len(value) - len(b.data)
	if needed > 0 {
		b.start = (b.start + needed) % len(b.data)
		b.length -= needed
		b.dropped += uint64(needed)
	}
	end := (b.start + b.length) % len(b.data)
	first := min(len(value), len(b.data)-end)
	copy(b.data[end:end+first], value[:first])
	copy(b.data[:len(value)-first], value[first:])
	b.length += len(value)
	return len(value), nil
}

func (b *diagnosticRing) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]byte, b.length)
	first := min(b.length, len(b.data)-b.start)
	copy(result, b.data[b.start:b.start+first])
	copy(result[first:], b.data[:b.length-first])
	return result
}

func (b *diagnosticRing) status() (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.length, b.dropped > 0
}

func (o *Owner) Start(ctx context.Context, spec Spec) (Snapshot, error) {
	if err := o.enter(ctx); err != nil {
		return Snapshot{}, err
	}
	defer o.leave()
	if o.reviewRequired {
		return o.snapshot(), ErrReviewRequired
	}
	if o.current != nil {
		return o.snapshot(), ErrAlreadyRunning
	}
	if validateSpec(spec) != nil {
		return o.snapshot(), ErrInvalid
	}
	process, err := startProcess(spec)
	if err != nil {
		o.state = StateStopped
		if errors.Is(err, ErrInvalid) {
			return o.snapshot(), ErrInvalid
		}
		return o.snapshot(), ErrUnavailable
	}
	o.current = process
	o.state = StateStarting
	o.diagnosticsMu.Lock()
	o.lastDiagnostics = process.diagnostics
	o.diagnosticsMu.Unlock()

	startCtx, cancel := context.WithTimeout(ctx, spec.ReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(spec.ProbeInterval)
	defer ticker.Stop()
	for {
		if process.exited() {
			return o.failStart(process, ErrProcessExited)
		}
		ready, probeErr := spec.Ready(startCtx)
		if probeErr != nil {
			return o.failStart(process, ErrNotReady)
		}
		if process.exited() {
			return o.failStart(process, ErrProcessExited)
		}
		if ready {
			process.ready = true
			o.generation++
			o.state = StateReady
			return o.snapshot(), nil
		}
		select {
		case <-startCtx.Done():
			return o.failStart(process, ErrNotReady)
		case <-process.done:
			return o.failStart(process, ErrProcessExited)
		case <-ticker.C:
		}
	}
}

// Stop performs a bounded graceful shutdown even if the request context was
// canceled. Once accepted, service cleanup must not be abandoned mid-signal.
func (o *Owner) Stop(ctx context.Context) (Snapshot, error) {
	if ctx == nil || o == nil || o.gate == nil {
		return Snapshot{}, ErrUnavailable
	}
	if err := o.enter(context.Background()); err != nil {
		return Snapshot{}, err
	}
	defer o.leave()
	if o.current == nil {
		if o.reviewRequired {
			return o.snapshot(), ErrReviewRequired
		}
		o.state = StateStopped
		return o.snapshot(), nil
	}
	process := o.current
	if process.stopAttempted {
		// The earlier stop already had an uncertain or forced outcome. Only
		// verify that the owned group is gone; never signal it a second time,
		// and never let cleanup erase the review state.
		if verifyProcessGroupExited(process) != nil {
			o.reviewRequired = true
			o.state = StateReviewRequired
			return o.snapshot(), ErrReviewRequired
		}
		o.current = nil
		o.reviewRequired = true
		o.state = StateReviewRequired
		return o.snapshot(), ErrReviewRequired
	}
	unexpectedExit := process.ready && process.exited()
	o.state = StateStopping
	stopErr := stopProcess(process)
	if stopErr != nil {
		o.reviewRequired = true
		o.state = StateReviewRequired
		return o.snapshot(), ErrReviewRequired
	}
	o.current = nil
	if unexpectedExit {
		o.reviewRequired = true
		o.state = StateReviewRequired
		return o.snapshot(), ErrReviewRequired
	}
	o.state = StateStopped
	return o.snapshot(), nil
}

// Observe reports the current in-process lifecycle state without starting,
// stopping, adopting or restarting anything. Once a process that previously
// passed readiness exits, the Owner permanently requires review; a replacement
// process is never started implicitly.
func (o *Owner) Observe(ctx context.Context) (Snapshot, error) {
	if err := o.enter(ctx); err != nil {
		return Snapshot{}, err
	}
	defer o.leave()
	if o.reviewRequired {
		return o.snapshot(), ErrReviewRequired
	}
	if o.current == nil {
		o.state = StateStopped
		return o.snapshot(), nil
	}
	if o.current.ready && o.current.exited() {
		o.reviewRequired = true
		o.state = StateReviewRequired
		return o.snapshot(), ErrReviewRequired
	}
	return o.snapshot(), nil
}

func (o *Owner) enter(ctx context.Context) error {
	if o == nil || ctx == nil || ctx.Err() != nil || o.gate == nil {
		return ErrUnavailable
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	if ctx.Err() != nil {
		<-o.gate
		return ErrUnavailable
	}
	return nil
}

func (o *Owner) leave() { <-o.gate }

func (o *Owner) snapshot() Snapshot {
	pid := 0
	var diagnostics *diagnosticRing
	if o.current != nil {
		pid = o.current.pid
		diagnostics = o.current.diagnostics
	} else {
		o.diagnosticsMu.RLock()
		diagnostics = o.lastDiagnostics
		o.diagnosticsMu.RUnlock()
	}
	return snapshot(o.state, o.generation, pid, diagnostics)
}

func (o *Owner) failStart(process *managedProcess, cause error) (Snapshot, error) {
	stopErr := stopProcess(process)
	if stopErr != nil {
		o.reviewRequired = true
		o.state = StateReviewRequired
		return o.snapshot(), errors.Join(cause, ErrReviewRequired)
	}
	o.current = nil
	o.state = StateStopped
	return o.snapshot(), cause
}

func validateSpec(spec Spec) error {
	if !filepath.IsAbs(spec.Executable) || filepath.Clean(spec.Executable) != spec.Executable ||
		strings.ContainsRune(spec.Executable, '\x00') || spec.Ready == nil ||
		spec.ReadyTimeout <= 0 || spec.ReadyTimeout > maxReadyTimeout ||
		spec.ProbeInterval < 10*time.Millisecond || spec.ProbeInterval > maxProbePeriod ||
		spec.StopTimeout <= 0 || spec.StopTimeout > maxStopTimeout || len(spec.Args) > 64 {
		return ErrInvalid
	}
	for _, arg := range spec.Args {
		if len(arg) > 4096 || strings.ContainsRune(arg, '\x00') {
			return ErrInvalid
		}
	}
	return nil
}

func startProcess(spec Spec) (*managedProcess, error) {
	executable, err := openExecutable(spec.Executable)
	if err != nil {
		return nil, err
	}
	diagnostics := newDiagnosticRing()
	command := exec.Command("/proc/self/fd/3")
	command.Args = append([]string{spec.Executable}, spec.Args...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{executable}
	command.Stdout, command.Stderr = diagnostics, diagnostics
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		_ = executable.Close()
		return nil, err
	}
	_ = executable.Close()
	process := &managedProcess{command: command, pid: command.Process.Pid,
		done: make(chan struct{}), stopTimeout: spec.StopTimeout, diagnostics: diagnostics}
	go process.wait()
	return process, nil
}

func openExecutable(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), "managed-service-executable")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalid
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0111 == 0 || stat.Mode&0022 != 0 {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func stopProcess(process *managedProcess) error {
	if process == nil {
		return nil
	}
	if process.stopAttempted {
		return ErrReviewRequired
	}
	process.stopAttempted = true
	alive, err := processGroupAlive(process.pid)
	if err != nil {
		return ErrReviewRequired
	}
	if alive {
		if err := syscall.Kill(-process.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return ErrReviewRequired
		}
	}
	clean, err := awaitProcessGroupExit(process, process.stopTimeout)
	if err != nil {
		return ErrReviewRequired
	}
	if clean {
		return nil
	}
	alive, err = processGroupAlive(process.pid)
	if err != nil {
		return ErrReviewRequired
	}
	if alive {
		if err := syscall.Kill(-process.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return ErrReviewRequired
		}
	}
	clean, err = awaitProcessGroupExit(process, forcedWait)
	if err != nil || !clean {
		return ErrReviewRequired
	}
	return ErrReviewRequired
}

func verifyProcessGroupExited(process *managedProcess) error {
	if process == nil || process.pid <= 1 || !process.exited() {
		return ErrReviewRequired
	}
	alive, err := processGroupAlive(process.pid)
	if err != nil || alive {
		return ErrReviewRequired
	}
	return nil
}

func awaitProcessGroupExit(process *managedProcess, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(probeWait)
	defer ticker.Stop()
	for {
		alive, err := processGroupAlive(process.pid)
		if err != nil {
			return false, err
		}
		if !alive && process.exited() {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		<-ticker.C
	}
}

func processGroupAlive(pid int) (bool, error) {
	err := syscall.Kill(-pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	return false, err
}

var _ io.Writer = (*diagnosticRing)(nil)

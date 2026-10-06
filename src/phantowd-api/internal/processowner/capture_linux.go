//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CaptureOwner retains one fixed command and one regular read-only stdin
// description. The caller must exclusively own its shared input offset/content.
// It deliberately excludes block/character devices and per-call inputs.
type CaptureOwner struct {
	self                          *CaptureOwner
	gate                          chan struct{}
	spec                          CaptureSpec
	executable, input             *os.File
	executableStat, inputStat     unix.Stat_t
	executableDigest, inputDigest [32]byte
	current                       *managedProcess
	consumed, review, closed      bool
	closeFailed                   bool
	// Only a fixed guarded QEMU constructor populates these private inputs.
	// Generic CaptureSpec has no descriptor-injection option.
	fixtureInputs      []*os.File
	fixtureInputsValid func() bool
}

func NewCapture(spec CaptureSpec, executable, input *os.File) (*CaptureOwner, error) {
	if !filepath.IsAbs(spec.ExecutableLabel) || filepath.Clean(spec.ExecutableLabel) != spec.ExecutableLabel ||
		strings.ContainsRune(spec.ExecutableLabel, '\x00') || len(spec.ExecutableLabel) > 4096 ||
		len(spec.Args) > 64 || spec.Timeout < time.Second || spec.Timeout > 30*time.Second ||
		spec.StopTimeout < 10*time.Millisecond || spec.StopTimeout > time.Second || !validCredentials(spec.RunAs) {
		return nil, ErrInvalid
	}
	for _, arg := range spec.Args {
		if len(arg) > 4096 || strings.ContainsRune(arg, '\x00') {
			return nil, ErrInvalid
		}
	}
	c := &CaptureOwner{gate: make(chan struct{}, 1), spec: spec}
	c.self = c
	c.spec.Args = slices.Clone(spec.Args)
	if spec.RunAs != nil {
		credentials := *spec.RunAs
		credentials.SupplementaryGIDs = slices.Clone(spec.RunAs.SupplementaryGIDs)
		c.spec.RunAs = &credentials
	}
	keep := false
	defer func() {
		if !keep {
			_ = c.release()
		}
	}()
	var err error
	c.executable, err = duplicateExecutable(executable)
	if err != nil {
		return nil, ErrInvalid
	}
	c.input, err = duplicateReadOnlyRegular(input)
	if err != nil || unix.Fstat(int(c.executable.Fd()), &c.executableStat) != nil ||
		unix.Fstat(int(c.input.Fd()), &c.inputStat) != nil || c.inputStat.Size < 0 ||
		c.inputStat.Size > MaxCaptureInput {
		return nil, ErrInvalid
	}
	offset, err := unix.Seek(int(c.input.Fd()), 0, 1)
	if err != nil || offset != 0 {
		return nil, ErrInvalid
	}
	c.executableDigest, err = captureDigest(c.executable, c.executableStat, MaxCaptureExecutable)
	if err != nil {
		return nil, ErrInvalid
	}
	c.inputDigest, err = captureDigest(c.input, c.inputStat, MaxCaptureInput)
	if err != nil {
		return nil, ErrInvalid
	}
	keep = true
	return c, nil
}

func (c *CaptureOwner) enter(ctx context.Context) error {
	if c == nil || c.self != c || c.gate == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

func (c *CaptureOwner) inputsUnchanged() bool {
	if c.executable == nil || c.input == nil || trustedExecutable(c.executable) != nil {
		return false
	}
	if c.fixtureInputsValid != nil && !c.fixtureInputsValid() {
		return false
	}
	var code, input unix.Stat_t
	if unix.Fstat(int(c.executable.Fd()), &code) != nil || unix.Fstat(int(c.input.Fd()), &input) != nil ||
		!sameCaptureObject(code, c.executableStat) || !sameCaptureObject(input, c.inputStat) {
		return false
	}
	codeDigest, err := captureDigest(c.executable, code, MaxCaptureExecutable)
	if err != nil || codeDigest != c.executableDigest {
		return false
	}
	inputDigest, err := captureDigest(c.input, input, MaxCaptureInput)
	return err == nil && inputDigest == c.inputDigest
}

// Bounded descriptor reads do not change the shared stdin offset. These hashes
// observe drift only: they are not authenticated expected release digests or an
// atomic snapshot against a concurrently writing trusted owner.
func captureDigest(file *os.File, before unix.Stat_t, limit int64) ([32]byte, error) {
	if before.Size < 0 || before.Size > limit {
		return [32]byte{}, ErrInvalid
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.NewSectionReader(file, 0, before.Size))
	var after unix.Stat_t
	if err != nil || count != before.Size || unix.Fstat(int(file.Fd()), &after) != nil || !sameCaptureObject(before, after) {
		return [32]byte{}, ErrInvalid
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func sameCaptureObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Rdev == b.Rdev && a.Size == b.Size &&
		a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Capture is single-use: even an exec failure consumes this fixed input. No
// readiness loop, path reopen, retry, restart or adoption occurs.
func (c *CaptureOwner) Capture(ctx context.Context) (CaptureResult, error) {
	if err := c.enter(ctx); err != nil {
		return CaptureResult{}, err
	}
	defer func() { <-c.gate }()
	if c.closed {
		return CaptureResult{}, ErrUnavailable
	}
	if c.review {
		return CaptureResult{}, ErrReviewRequired
	}
	if c.consumed {
		return CaptureResult{}, ErrCaptureConsumed
	}
	if !c.inputsUnchanged() {
		c.review = true
		return CaptureResult{}, ErrReviewRequired
	}
	offset, err := unix.Seek(int(c.input.Fd()), 0, 1)
	if err != nil || offset != 0 {
		c.review = true
		return CaptureResult{}, ErrReviewRequired
	}
	operation, cancel := context.WithTimeout(ctx, c.spec.Timeout)
	defer cancel()
	if err := operation.Err(); err != nil {
		return CaptureResult{}, err
	}
	c.consumed = true
	stdout, stderr := newCaptureBuffer(MaxCaptureStdout), newCaptureBuffer(MaxCaptureStderr)
	command := exec.Command("/proc/self/fd/3")
	command.Args = append([]string{c.spec.ExecutableLabel}, c.spec.Args...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.ExtraFiles = append([]*os.File{c.executable}, c.fixtureInputs...)
	command.Stdin, command.Stdout, command.Stderr = c.input, stdout, stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if c.spec.RunAs != nil {
		command.SysProcAttr.Credential = &syscall.Credential{
			Uid: c.spec.RunAs.UID, Gid: c.spec.RunAs.GID,
			Groups: slices.Clone(c.spec.RunAs.SupplementaryGIDs),
		}
	}
	command.WaitDelay = time.Second
	if command.Start() != nil {
		return CaptureResult{}, ErrUnavailable
	}
	process := &managedProcess{command: command, pid: command.Process.Pid,
		done: make(chan struct{}), stopTimeout: c.spec.StopTimeout}
	c.current = process
	go process.wait()
	select {
	case <-process.done:
	case <-operation.Done():
	}
	if err := operation.Err(); err != nil {
		c.review = true
		// Reuse the existing owned-group cleanup. Forced/uncertain cleanup never
		// drops current; a later explicit Settled can verify absence, not retry.
		if stopProcess(process) == nil {
			c.current = nil
		}
		return CaptureResult{}, err
	}
	if err := c.verifySettled(); err != nil {
		return CaptureResult{}, err
	}
	if !c.inputsUnchanged() {
		c.review = true
		return CaptureResult{}, ErrReviewRequired
	}
	if stdout.overflow || stderr.overflow {
		return CaptureResult{}, ErrCaptureOutput
	}
	process.waitMu.Lock()
	waitErr := process.waitErr
	process.waitMu.Unlock()
	var exited *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exited) {
		return CaptureResult{}, ErrCaptureResult
	}
	if command.ProcessState == nil {
		return CaptureResult{}, ErrCaptureResult
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return CaptureResult{}, ErrCaptureResult
	}
	if err := operation.Err(); err != nil {
		return CaptureResult{}, err
	}
	if status.Signaled() {
		return CaptureResult{Kind: CaptureSignaled, ExitCode: -1}, nil
	}
	if !status.Exited() || status.ExitStatus() < 0 || status.ExitStatus() > 255 {
		return CaptureResult{}, ErrCaptureResult
	}
	if err := operation.Err(); err != nil {
		return CaptureResult{}, err
	}
	return CaptureResult{Kind: CaptureExited, ExitCode: status.ExitStatus(), Stdout: stdout.data, Stderr: stderr.data}, nil
}

func (c *CaptureOwner) verifySettled() error {
	if c.current == nil {
		return nil
	}
	if verifyProcessGroupExited(c.current) != nil {
		c.review = true
		return ErrReviewRequired
	}
	c.current = nil
	return nil
}

// Settled only verifies child/group absence. It never signals, retries capture
// or clears review; it is allowed after Close because absence remains true.
func (c *CaptureOwner) Settled(ctx context.Context) (bool, error) {
	if err := c.enter(ctx); err != nil {
		return false, err
	}
	defer func() { <-c.gate }()
	if err := c.verifySettled(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}

func (c *CaptureOwner) Close(ctx context.Context) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.closed {
		if c.closeFailed {
			return ErrReviewRequired
		}
		return nil
	}
	if err := c.verifySettled(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.closed = true
	if c.release() != nil {
		c.review = true
		c.closeFailed = true
		return ErrReviewRequired
	}
	return nil
}

func (c *CaptureOwner) release() error {
	var err error
	for _, file := range append([]*os.File{c.executable, c.input}, c.fixtureInputs...) {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	c.executable, c.input = nil, nil
	c.fixtureInputs, c.fixtureInputsValid = nil, nil
	return err
}

// No embedded Buffer/ReadFrom: io.Copy cannot bypass the acceptance bound.
// Go uses one copy worker per stream; data is read only after Wait joins both.
type captureBuffer struct {
	data     []byte
	limit    int
	overflow bool
}

func newCaptureBuffer(limit int) *captureBuffer {
	return &captureBuffer{data: make([]byte, 0, limit), limit: limit}
}

func (b *captureBuffer) Write(value []byte) (int, error) {
	if b.overflow || len(value) > b.limit-len(b.data) {
		b.overflow = true
		return 0, ErrCaptureOutput
	}
	b.data = append(b.data, value...)
	return len(value), nil
}

func (*CaptureOwner) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CaptureOwner) UnmarshalJSON([]byte) error   { return ErrInvalid }

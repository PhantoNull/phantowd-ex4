//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const pendingOpenNoticeQEMU = "PHANTOWD_SMB_WRITE_CLIENT_OPEN_NOTICE scope=qemu-only proof=false\n"
const pendingCloseNoticeQEMU = "PHANTOWD_SMB_WRITE_CLIENT_CLOSE_NOTICE scope=qemu-only proof=false\n"

// First corrected ARMv5 SMB3 handshake measured5.557s, beyond the constructor-
// only checkpoint's unqualified5s guess. Bound this distinct startup at the
// existing native daemon's12s ceiling; parent cancellation still wins. Explicit
// CLOSE keeps5s. No existing launcher/campaign or protocol deadline changes.
const pendingClientStartTimeoutQEMU = 12 * time.Second

// PendingClientQEMU is a fixed, single-use process adapter, not complete code,
// storage or SMB authority. Trusted composition retains and rechecks the whole
// root/helper census before/after Start and throughout this adapter's lifetime.
// Readiness is client telemetry ONLY, never a server/session/object witness.
// There is intentionally no write operation before original-object admission.
type PendingClientQEMU struct {
	self                         *PendingClientQEMU
	gate                         chan struct{}
	pins                         []*os.File // helper, read-directory root, client
	identities                   []unix.Stat_t
	secret                       []byte
	control                      *os.File
	process                      *managedProcess
	originalProc                 *os.File
	originalGeneration           pendingProcGenerationQEMU
	connection                   *pendingConnectionQEMU
	stdout, stderr               *diagnosticRing
	started, settled, review     bool
	closeSent, closed, stopTried bool
	releaseErr, stopErr          error
}

func validPendingSecretQEMU(secret []byte) bool {
	if len(secret) == 0 || len(secret) > 128 {
		return false
	}
	for _, value := range secret {
		if value < 33 || value > 126 {
			return false
		}
	}
	return true
}

// Fixed fixture constructor. No command, path, account, profile or per-call
// descriptor injection; secret copied once and sent only through a fresh pipe.
func NewPendingClientQEMU(helper, root, client *os.File, secret []byte) (_ *PendingClientQEMU, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if runtime.GOARCH != "arm" || err != nil || string(model) != "ARM Versatile PB\x00" ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || !validPendingSecretQEMU(secret) {
		return nil, ErrInvalid
	}
	c := &PendingClientQEMU{gate: make(chan struct{}, 1), secret: bytes.Clone(secret)}
	c.self = c
	defer func() {
		if result != nil {
			result = errors.Join(result, c.release())
		}
	}()
	for index, source := range []*os.File{helper, root, client} {
		var pin *os.File
		if index == 1 {
			pin, err = duplicatePendingRootQEMU(source)
		} else {
			pin, err = duplicateExecutable(source)
		}
		if err != nil {
			return nil, err
		}
		c.pins = append(c.pins, pin)
		var identity unix.Stat_t
		if unix.Fstat(int(pin.Fd()), &identity) != nil || identity.Gid != 0 ||
			(index != 1 && (identity.Mode != unix.S_IFREG|0555 || identity.Nlink != 1 || identity.Size <= 0 || identity.Size > 1<<20)) {
			return nil, ErrInvalid
		}
		c.identities = append(c.identities, identity)
	}
	return c, nil
}

func duplicatePendingRootQEMU(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "fixed-pending-client-root")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var info unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || flags&unix.O_DIRECTORY == 0 ||
		unix.Fstat(fd, &info) != nil || info.Mode != unix.S_IFDIR|0755 || info.Uid != 0 || info.Gid != 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		fs.Flags&(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV {
		return nil, errors.Join(ErrInvalid, pin.Close())
	}
	return pin, nil
}

func (c *PendingClientQEMU) enter(ctx context.Context) error {
	if c == nil || c.self != c || c.gate == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	if c.closed {
		<-c.gate
		return ErrUnavailable
	}
	return nil
}

// Does not qualify content. Containing composition must revalidate its complete
// original input tuple independently, not accept this metadata observation.
func (c *PendingClientQEMU) recheckPins() error {
	if len(c.pins) != 3 || len(c.identities) != 3 {
		return ErrInvalid
	}
	for index, pin := range c.pins {
		if pin == nil {
			return ErrInvalid
		}
		var actual unix.Stat_t
		if unix.Fstat(int(pin.Fd()), &actual) != nil || actual != c.identities[index] {
			return ErrReviewRequired
		}
	}
	return nil
}

// Separate writer objects force os/exec to give stdout/stderr DISTINCT pipes.
// Reusing the same writer causes Go to alias them, rejected by the fixed ABI.
func pendingCommandQEMU(pins []*os.File, control, secret *os.File, stdout, stderr *diagnosticRing) *exec.Cmd {
	command := exec.Command("/proc/self/fd/6")
	command.Args = []string{"phantowd-pending-write-launcher"}
	command.Dir, command.Env = "/", []string{"LC_ALL=C"}
	command.Stdin, command.Stdout, command.Stderr = control, stdout, stderr
	command.ExtraFiles = []*os.File{secret, pins[1], pins[2], pins[0]}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: 0, Gid: 0}}
	command.WaitDelay = time.Second
	return command
}

// Accept only exact ordered notices or an incomplete prefix awaiting bytes.
// No raw output is returned, logged or treated as SMB/identity/I/O proof.
func pendingNoticesQEMU(stdout, stderr []byte, closing bool) (bool, error) {
	if len(stderr) != 0 || len(stdout) > 4096 {
		return false, ErrReviewRequired
	}
	expected := []byte(pendingOpenNoticeQEMU)
	if closing {
		expected = append(expected, []byte(pendingCloseNoticeQEMU)...)
	}
	if !bytes.HasPrefix(expected, stdout) {
		return false, ErrReviewRequired
	}
	return bytes.Equal(stdout, expected), nil
}

func (c *PendingClientQEMU) notices(closing bool) (bool, error) {
	if c.stdout == nil || c.stderr == nil {
		return false, ErrInvalid
	}
	_, outDropped := c.stdout.status()
	_, errDropped := c.stderr.status()
	if outDropped || errDropped {
		return false, ErrReviewRequired
	}
	out, diagnostic := c.stdout.snapshot(), c.stderr.snapshot()
	defer clear(out)
	defer clear(diagnostic)
	return pendingNoticesQEMU(out, diagnostic, closing)
}

func (c *PendingClientQEMU) fail(cause error) error {
	c.review = true
	clear(c.secret)
	c.secret = nil
	if c.process != nil && !c.stopTried {
		c.stopTried = true
		c.stopErr = stopProcess(c.process)
	}
	return errors.Join(ErrReviewRequired, cause, c.stopErr)
}

// Single-use start. The fixed OPEN notice is availability ONLY; caller must
// independently bind the original server/session/open/object before proceeding.
func (c *PendingClientQEMU) Start(ctx context.Context) (result error) {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.review || c.started || c.releaseErr != nil || !validPendingSecretQEMU(c.secret) {
		return ErrReviewRequired
	}
	if err := c.recheckPins(); err != nil {
		return c.fail(err)
	}
	c.started = true
	controlR, controlW, err := os.Pipe()
	if err != nil {
		return c.fail(err)
	}
	c.control = controlW
	defer func() {
		if err := controlR.Close(); err != nil {
			result = c.fail(errors.Join(result, err))
		}
	}()
	secretR, secretW, err := os.Pipe()
	if err != nil {
		return c.fail(err)
	}
	defer func() {
		if err := secretR.Close(); err != nil {
			result = c.fail(errors.Join(result, err))
		}
	}()
	// Empty fresh anonymous pipe; the bounded input is smaller than PIPE_BUF.
	input := append(bytes.Clone(c.secret), '\n')
	written, writeErr := secretW.Write(input)
	clear(input)
	clear(c.secret)
	c.secret = nil
	closeErr := secretW.Close()
	if writeErr != nil || written != len(input) || closeErr != nil {
		return c.fail(errors.Join(writeErr, closeErr))
	}
	c.stdout, c.stderr = newDiagnosticRing(), newDiagnosticRing()
	command := pendingCommandQEMU(c.pins, controlR, secretR, c.stdout, c.stderr)
	if err := ctx.Err(); err != nil {
		return c.fail(err)
	}
	if err := command.Start(); err != nil {
		return c.fail(err)
	}
	c.process = &managedProcess{command: command, pid: command.Process.Pid, done: make(chan struct{}), stopTimeout: time.Second}
	// Capture the owned process before permitting Wait to reap it. Binding
	// duplicates this original reference, never reopens a later numeric PID.
	procFD, procErr := unix.Open("/proc/"+strconv.Itoa(c.process.pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if procErr == nil {
		c.originalProc = os.NewFile(uintptr(procFD), "original-owned-pending-client")
		c.originalGeneration, procErr = pendingProcGenerationReadQEMU(c.originalProc)
		if procErr == nil && (c.originalGeneration.pid != c.process.pid || c.originalGeneration.parent != os.Getpid() || c.originalGeneration.group != c.process.pid) {
			procErr = ErrUnavailable
		}
	}
	go c.process.wait()
	if procErr != nil {
		return c.fail(procErr)
	}
	bounded, cancel := context.WithTimeout(ctx, pendingClientStartTimeoutQEMU)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := c.notices(false)
		if err != nil || c.process.exited() {
			return c.fail(errors.Join(ErrNotReady, err))
		}
		if ready {
			return c.recheckAfterStart()
		}
		select {
		case <-bounded.Done():
			return c.fail(bounded.Err())
		case <-ticker.C:
		}
	}
}

func (c *PendingClientQEMU) recheckAfterStart() error {
	if err := c.recheckPins(); err != nil {
		return c.fail(err)
	}
	return nil
}

// One explicit protocol close, never a retry/reopen/restart. A successful return
// verifies exit0 and original group absence, not server durability or recovery.
func (c *PendingClientQEMU) CloseClient(ctx context.Context) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.review || !c.started || c.closeSent || c.process == nil || c.control == nil {
		return ErrReviewRequired
	}
	if err := c.recheckPins(); err != nil {
		return c.fail(err)
	}
	c.closeSent = true
	if c.connection != nil {
		pair, err := c.connection.observeQEMU(ctx, c)
		if err != nil || pair != c.connection.pair {
			return c.fail(errors.Join(ErrUnavailable, err))
		}
	}
	written, err := c.control.Write([]byte{'C'})
	if err != nil || written != 1 {
		return c.fail(errors.Join(ErrUnavailable, err))
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-c.process.done:
	case <-bounded.Done():
		return c.fail(bounded.Err())
	}
	c.process.waitMu.Lock()
	waitErr := c.process.waitErr
	c.process.waitMu.Unlock()
	ready, noticeErr := c.notices(true)
	if waitErr != nil || noticeErr != nil || !ready || verifyProcessGroupExited(c.process) != nil {
		return c.fail(errors.Join(ErrReviewRequired, waitErr, noticeErr))
	}
	if err := c.recheckPins(); err != nil {
		return c.fail(err)
	}
	c.settled = true
	return nil
}

// Stop quarantines even a clean local kill: protocol outcome is uncertain.
// Pins remain owned in review; repeated calls never signal/restart again.
func (c *PendingClientQEMU) Stop(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	if err := c.enter(context.Background()); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	return c.fail(ErrReviewRequired)
}

func (c *PendingClientQEMU) Close() error {
	if c == nil || c.self != c || c.gate == nil {
		return ErrUnavailable
	}
	select {
	case c.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	defer func() { <-c.gate }()
	if c.review || c.releaseErr != nil {
		return ErrReviewRequired
	}
	if c.closed {
		return nil
	}
	if c.started && (!c.settled || verifyProcessGroupExited(c.process) != nil) {
		return ErrAlreadyRunning
	}
	if c.connection != nil {
		if _, err := pendingProcGenerationReadQEMU(c.connection.peer); err == nil {
			return ErrBusy // The separately owned original server worker is still live.
		} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			c.review = true
			return ErrReviewRequired
		}
	}
	c.closed = true
	if err := c.release(); err != nil {
		c.releaseErr = err
		return ErrReviewRequired
	}
	return nil
}

func (c *PendingClientQEMU) release() error {
	clear(c.secret)
	c.secret = nil
	if c.connection != nil {
		if err := c.connection.releaseQEMU(); err != nil {
			return err
		}
		c.connection = nil
	}
	if c.originalProc != nil {
		if err := c.originalProc.Close(); err != nil {
			return err
		}
		c.originalProc = nil
	}
	if c.control != nil {
		if err := c.control.Close(); err != nil {
			return err
		}
		c.control = nil
	}
	for len(c.pins) > 0 {
		if err := c.pins[0].Close(); err != nil {
			return err
		}
		c.pins = c.pins[1:]
	}
	return nil
}

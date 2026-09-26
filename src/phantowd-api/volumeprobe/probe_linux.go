// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var active atomic.Bool

// Inspect accepts an already eligible O_RDONLY descriptor; it does NOT decide
// device eligibility, scan completeness, clone uniqueness or WD compatibility.
// It duplicates the descriptor without taking ownership of source. The caller
// must exclusively own source's shared open-file description during this call:
// probing may move its offset. Keep media and mount topology stable externally.
// The fixed helper must be installed in trusted, non-user-writable firmware.
// Cancellation kills its process group and waits for reaping; uninterruptible
// kernel I/O may delay that wait. The process-wide slot remains held meanwhile.
func Inspect(ctx context.Context, source *os.File) (Result, error) {
	return inspect(ctx, source, "/usr/libexec/phantowd-volume-probe", 8*time.Second)
}

func inspect(ctx context.Context, source *os.File, executable string, timeout time.Duration) (Result, error) {
	if ctx == nil || source == nil {
		return Result{}, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !active.CompareAndSwap(false, true) {
		return Result{}, ErrBusy
	}
	defer active.Store(false)
	input, before, kind, err := retain(source)
	if err != nil {
		return Result{}, err
	}
	defer input.Close()
	return inspectPinned(ctx, input, before, kind, executable, timeout)
}

func retain(source *os.File) (*os.File, unix.Stat_t, string, error) {
	if source == nil {
		return nil, unix.Stat_t{}, "", ErrUnsafe
	}
	// SyscallConn prevents a concurrent Close from recycling the descriptor
	// between extraction and duplication. The duplicate outlives source.
	connection, err := source.SyscallConn()
	if err != nil {
		return nil, unix.Stat_t{}, "", ErrUnsafe
	}
	fd := -1
	var duplicateErr error
	err = connection.Control(func(original uintptr) {
		fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || duplicateErr != nil || fd < 0 {
		if fd >= 0 {
			unix.Close(fd)
		}
		return nil, unix.Stat_t{}, "", ErrUnsafe
	}
	input := os.NewFile(uintptr(fd), "volume-probe-input")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var before unix.Stat_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || unix.Fstat(fd, &before) != nil {
		input.Close()
		return nil, unix.Stat_t{}, "", ErrUnsafe
	}
	kind := "regular-image"
	switch before.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFBLK:
		kind = "block-device"
	default:
		input.Close()
		return nil, unix.Stat_t{}, "", ErrUnsafe
	}
	return input, before, kind, nil
}

// The caller retains the descriptor and process-wide slot through this call.
func inspectPinned(ctx context.Context, input *os.File, before unix.Stat_t, kind, executable string, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable)
	cmd.Stdin = input
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin", "LIBBLKID_DEBUG=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	var output, diagnostic boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	err := cmd.Run()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil || diagnostic.Len() != 0 {
		return Result{}, ErrProbe
	}
	var after unix.Stat_t
	if unix.Fstat(int(input.Fd()), &after) != nil || !sameObject(before, after) {
		return Result{}, ErrUnsafe
	}
	result, err := decode(bytes.NewReader(output.Bytes()))
	if err != nil {
		return Result{}, err
	}
	if result.SourceKind != kind {
		return Result{}, ErrResponse
	}
	return result, nil
}

func sameObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Rdev == b.Rdev &&
		a.Size == b.Size && a.Mode == b.Mode && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Do not embed bytes.Buffer: its promoted ReadFrom would let io.Copy bypass
// Write's limit when collecting child pipes.
type boundedOutput struct{ buffer bytes.Buffer }

func (out *boundedOutput) Len() int      { return out.buffer.Len() }
func (out *boundedOutput) Bytes() []byte { return out.buffer.Bytes() }

func (out *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maxOutput-out.Len() {
		return 0, ErrResponse
	}
	return out.buffer.Write(data)
}

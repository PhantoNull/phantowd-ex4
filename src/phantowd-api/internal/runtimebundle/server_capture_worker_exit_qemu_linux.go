//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func captureWorkerExitFixtureQEMU() bool {
	if serverObserverCodeGuardQEMU() != nil {
		return false
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return false
	}
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_worker_exit_fixture=1" {
			return true
		}
	}
	return false
}

// Test-only fault injection into the original synthetic worker. No caller PID,
// arbitrary process, numeric-PID signaling or installed/product entry point.
func (r *serverObserverRuntimeQEMU) killCaptureWorkerForFixtureQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if !captureWorkerExitFixtureQEMU() || r.review || r.closed || r.captureWorker == nil || r.captureWorker.proc == nil || r.captureWorker.file == nil {
		return ErrInvalid
	}
	if err := r.checkInputs(ctx); err != nil {
		return err
	}
	w := r.captureWorker
	base := "/proc/self/fd/" + strconv.FormatUint(uint64(w.proc.Fd()), 10)
	start, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.pid)
	if err != nil || start != w.start || start == "" {
		return errors.Join(ErrMismatch, err)
	}
	pid, err := strconv.ParseInt(w.status.server.PID, 10, 31)
	if err != nil || pid <= 1 {
		return ErrInvalid
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	// The held proc generation must still be alive AFTER pidfd creation. If it
	// exited/recycled during binding, refuse without signaling any replacement.
	after, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.pid)
	if err != nil || after != start || ctx.Err() != nil {
		return errors.Join(ErrMismatch, err, ctx.Err())
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return err
	}
	wait := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	// Pinned kernel pidfs.c also reports HUP after the parent reaps the task.
	// IN is mandatory; no error/invalid/foreign event is accepted.
	if n, err := unix.Poll(wait, 2000); err != nil || n != 1 || wait[0].Revents&unix.POLLIN == 0 || wait[0].Revents & ^int16(unix.POLLIN|unix.POLLHUP) != 0 {
		return errors.Join(ErrMismatch, err)
	}
	return ctx.Err()
}

func captureWorkerExitProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t) error {
	if o == nil || r == nil || !captureWorkerExitFixtureQEMU() || r.channel == nil || r.channel.sequence != 1 {
		return ErrInvalid
	}
	if err := r.killCaptureWorkerForFixtureQEMU(ctx); err != nil {
		return err
	}
	if frame, err := o.readCaptureFrameQEMU(ctx); !errors.Is(err, ErrReviewRequired) || frame != (pendingServerPacketObservationQEMU{}) || !o.review || !r.review || r.channel.sequence != 1 {
		return errors.Join(ErrMismatch, err)
	}
	settled, err := o.captureAdapter.StoppedInReviewQEMU(ctx)
	if err != nil || !settled {
		return errors.Join(ErrMismatch, err)
	}
	stopped, err := r.Stop(ctx)
	if !errors.Is(err, ErrReviewRequired) || stopped.State != processowner.StateReviewRequired || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		return errors.Join(ErrMismatch, err)
	}
	if !errors.Is(o.close(), ErrReviewRequired) || !errors.Is(r.Close(), ErrReviewRequired) || !errors.Is(o.start(ctx), ErrReviewRequired) {
		return ErrMismatch
	}
	if _, err := r.Start(ctx); !errors.Is(err, ErrReviewRequired) {
		return ErrMismatch
	}
	if frame, err := o.readCaptureFrameQEMU(ctx); !errors.Is(err, ErrReviewRequired) || frame != (pendingServerPacketObservationQEMU{}) || r.channel.sequence != 1 {
		return ErrMismatch
	}
	for _, file := range []*os.File{r.captureWorker.file, r.captureWorker.proc, r.proc, r.channel.receiver, r.channel.sender, o.inputs.client.files[pendingClientObserverQEMU]} {
		if file == nil {
			return ErrMismatch
		}
		// Dead original proc references are not expected to resolve live task
		// attributes. Verify retention, not a fabricated live process snapshot.
		if _, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil {
			return fmt.Errorf("capture worker fault discarded original: %w", err)
		}
	}
	var held unix.Stat_t
	if unix.Fstat(int(original.Fd()), &held) != nil || !samePendingObjectQEMU(initial, held) {
		return ErrMismatch
	}
	if unix.Fstat(int(r.captureWorker.file.Fd()), &held) != nil || !samePendingObjectQEMU(initial, held) {
		return ErrMismatch
	}
	return ctx.Err()
}

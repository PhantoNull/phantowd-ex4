//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Private original server-side observation. Holding the proc directory and
// rechecking its start ticks prevents a replacement PID becoming continuity.
// This does NOT identify the remote client socket or libsmbclient handle.
type pendingServerOpenQEMU struct {
	runtime *NativeSambaRuntimeQEMU
	proc    *os.File
	status  pendingStatusQEMU
	start   string
}

func (r *NativeSambaRuntimeQEMU) observePendingServerOpenQEMU(ctx context.Context, original *os.File, initial unix.Stat_t) (witness *pendingServerOpenQEMU, result error) {
	if err := r.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-r.gate }()
	defer func() {
		if result != nil {
			r.owner.review = true // Containing fixture stops once and retains all pins.
		}
	}()
	observed, err := r.pendingStatusQEMU(ctx)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/proc/"+observed.server.PID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	witness = &pendingServerOpenQEMU{runtime: r, proc: os.NewFile(uintptr(fd), "original-pending-server-worker"), status: observed}
	witness.start, err = witness.verifyWorkerQEMU(original, initial)
	if err != nil {
		return witness, err // Retain even a partially inspected worker on refusal.
	}
	return witness, ctx.Err()
}

func (r *NativeSambaRuntimeQEMU) pendingStatusQEMU(ctx context.Context) (pendingStatusQEMU, error) {
	if r.closed || r.owner == nil || r.owner.review || r.pending != nil || !r.daemonAttempted || r.daemonPID <= 1 {
		return pendingStatusQEMU{}, ErrReviewRequired
	}
	// executeQEMU already performs the complete live-daemon admission on BOTH
	// sides of its worker. Do not hash the whole tuple again around those same
	// fences: the fixed parent/worker budget is part of the contract, too.
	output, err := r.executeQEMU(ctx, processowner.NativeSambaStatusQEMU, "", nil)
	defer clear(output)
	if err != nil {
		return pendingStatusQEMU{}, err
	}
	observed, err := parsePendingStatusQEMU(output)
	if err != nil {
		return pendingStatusQEMU{}, err
	}
	return observed, ctx.Err()
}

// Same runtime/worker generation/session/tree/open and same original local
// object, observed twice while the single original client remains open. No
// worker retry, re-login, path fallback or caller-supplied expected IDs.
func (w *pendingServerOpenQEMU) recheckQEMU(ctx context.Context, original *os.File, initial unix.Stat_t) (result error) {
	if w == nil || w.runtime == nil || w.proc == nil || w.start == "" {
		return ErrInvalid
	}
	r := w.runtime
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	defer func() {
		if result != nil {
			r.owner.review = true
		}
	}()
	start, err := w.verifyWorkerQEMU(original, initial)
	if err != nil || start != w.start {
		return errors.Join(ErrReviewRequired, err)
	}
	observed, err := r.pendingStatusQEMU(ctx)
	if err != nil || observed != w.status {
		return errors.Join(ErrReviewRequired, err)
	}
	start, err = w.verifyWorkerQEMU(original, initial)
	if err != nil || start != w.start {
		return errors.Join(ErrReviewRequired, err)
	}
	return ctx.Err()
}

func (w *pendingServerOpenQEMU) verifyWorkerQEMU(original *os.File, initial unix.Stat_t) (string, error) {
	if w == nil || w.runtime == nil || w.proc == nil || original == nil {
		return "", ErrInvalid
	}
	r := w.runtime
	base := "/proc/self/fd/" + strconv.FormatUint(uint64(w.proc.Fd()), 10)
	before, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.daemonPID)
	if err != nil {
		return "", fmt.Errorf("pending worker first stat: %w", err)
	}
	pid, err := strconv.ParseUint(w.status.server.PID, 10, 31)
	if err != nil {
		return "", fmt.Errorf("pending worker PID: %w", ErrMismatch)
	}
	group, err := unix.Getpgid(int(pid))
	actual, actualErr := os.Stat(base + "/exe")
	expected, expectedErr := r.owner.files["usr/sbin/smbd"].Stat()
	var held, server unix.Stat_t
	if err != nil || group != r.daemonPID || actualErr != nil || expectedErr != nil || !os.SameFile(actual, expected) ||
		unix.Fstat(int(original.Fd()), &held) != nil || unix.Stat(base+"/root/shares/writable/pending-write", &server) != nil ||
		!samePendingObjectQEMU(initial, held) || !samePendingObjectQEMU(initial, server) ||
		uint64(held.Dev) != w.status.device || uint64(held.Ino) != w.status.inode {
		return "", fmt.Errorf("pending worker code/group/local object: %w", ErrMismatch)
	}
	after, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.daemonPID)
	if err != nil || before != after {
		return "", errors.Join(ErrReviewRequired, err)
	}
	return before, nil
}

func pendingWorkerStatQEMU(base, pid string, daemon int) (string, error) {
	file, err := os.Open(base + "/stat")
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return "", err
	}
	return parsePendingWorkerStatQEMU(data, pid, daemon)
}

func parsePendingWorkerStatQEMU(data []byte, pid string, daemon int) (string, error) {
	if len(data) == 0 || len(data) > 4096 || daemon <= 1 || !pendingNumberQEMU(pid, 31, true) ||
		!strings.HasPrefix(string(data), pid+" (") {
		return "", ErrMismatch
	}
	// comm may contain spaces or ')'; the last ') ' precedes the fixed fields.
	end := strings.LastIndex(string(data), ") ")
	if end < len(pid)+2 {
		return "", ErrMismatch
	}
	fields := strings.Fields(string(data[end+2:]))
	parent := strconv.Itoa(daemon)
	if len(fields) < 20 || (fields[0] != "R" && fields[0] != "S" && fields[0] != "D") ||
		fields[1] != parent || fields[2] != parent || !pendingNumberQEMU(fields[19], 64, true) {
		return "", ErrMismatch
	}
	return fields[19], nil
}

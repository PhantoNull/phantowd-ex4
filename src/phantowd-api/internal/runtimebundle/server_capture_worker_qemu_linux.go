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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const serverCaptureStatusBootstrapQEMU = "usr/sbin/phantowd-server-capture-status-bootstrap"

// The unchanged native STATUS boundary enters CLONE_NEWNET without enabling
// interfaces. Pinned Samba source3/lib/interface.c emits this exact warning.
// Require the complete expected stream, never ignore arbitrary diagnostics.
const serverCaptureStatusReceiptQEMU = nativeCredentialHandoff + "WARNING: no network interfaces found\n"

func parseServerCaptureStatusResultQEMU(observed processowner.CaptureResult, runErr error) (pendingStatusQEMU, error) {
	if runErr != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 || string(observed.Stderr) != serverCaptureStatusReceiptQEMU {
		return pendingStatusQEMU{}, fmt.Errorf("capture STATUS result kind=%v exit=%d stdout_bytes=%d stderr_bytes=%d: %w", observed.Kind, observed.ExitCode, len(observed.Stdout), len(observed.Stderr), errors.Join(ErrMismatch, runErr))
	}
	return parseServerCaptureStatusQEMU(observed.Stdout)
}

// Original STATUS/proc/local-object witness only, NOT a remote FileId, TCP,
// module frame or request lease. The containing runtime owns it until stop.
type serverCaptureWorkerQEMU struct {
	proc   *os.File
	status pendingStatusQEMU
	start  string
}

// Caller holds r.gate. No caller-selected verb, argv, password or bootstrap.
func (r *serverObserverRuntimeQEMU) captureStatusLockedQEMU(ctx context.Context) (pendingStatusQEMU, error) {
	if r.closed || r.review || r.pid <= 1 || r.captureStatus != nil || r.code == nil {
		return pendingStatusQEMU{}, ErrReviewRequired
	}
	helper := r.code.code.files[serverCaptureStatusBootstrapQEMU]
	if helper == nil || r.code.code.files[serverCaptureModuleObjectQEMU] == nil || staticExecutable(helper) != nil {
		return pendingStatusQEMU{}, ErrInvalid
	}
	if err := r.checkInputs(ctx); err != nil {
		return pendingStatusQEMU{}, err
	}
	if err := r.checkProcess(); err != nil {
		return pendingStatusQEMU{}, err
	}
	if observed, err := r.daemon.Observe(ctx); err != nil || observed.State != processowner.StateReady || len(observed.Members) != 1 || observed.Members[0].Process.PID != r.pid {
		return pendingStatusQEMU{}, errors.Join(ErrMismatch, err)
	}
	input, err := sealedNativeCredentialInputQEMU(nil)
	if err != nil {
		return pendingStatusQEMU{}, err
	}
	fd, err := openBeneath(int(r.configuration.contents.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return pendingStatusQEMU{}, errors.Join(err, input.Close())
	}
	root := os.NewFile(uintptr(fd), "original-capture-status-configuration")
	config := [5]*os.File{root, r.configuration.contents.files["passwd"], r.configuration.contents.files["group"], r.configuration.contents.files["nsswitch.conf"], r.configuration.contents.files["samba/smb.conf"]}
	var state [7]*os.File
	for i, role := range sambaStateDirectories {
		state[i] = r.state.files[role]
	}
	capture, constructErr := processowner.NewNativeSambaCaptureQEMU(helper, input, config, state, processowner.NativeSambaStatusQEMU, "")
	// A partial/uncertain constructor remains reachable from its runtime.
	r.captureStatus = capture
	if err := errors.Join(constructErr, root.Close(), input.Close()); err != nil {
		return pendingStatusQEMU{}, err
	}
	if err := r.checkInputs(ctx); err != nil {
		return pendingStatusQEMU{}, err
	}
	observed, runErr := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	settled, settleErr := capture.Settled(context.Background())
	if !settled || settleErr != nil {
		return pendingStatusQEMU{}, errors.Join(ErrReviewRequired, settleErr, runErr)
	}
	if err := capture.Close(context.Background()); err != nil {
		return pendingStatusQEMU{}, err
	}
	r.captureStatus = nil
	status, err := parseServerCaptureStatusResultQEMU(observed, runErr)
	if err != nil {
		return pendingStatusQEMU{}, err
	}
	if err := r.checkInputs(ctx); err != nil {
		return pendingStatusQEMU{}, err
	}
	if err := r.checkProcess(); err != nil {
		return pendingStatusQEMU{}, err
	}
	if state, err := r.daemon.Observe(ctx); err != nil || state.State != processowner.StateReady || len(state.Members) != 1 || state.Members[0].Process.PID != r.pid {
		return pendingStatusQEMU{}, errors.Join(ErrMismatch, err)
	}
	return status, nil
}

// One initial independent observation, then exact original rechecks. No PID
// adoption on later calls. Original data is held by the containing OPEN probe.
func (r *serverObserverRuntimeQEMU) observeCaptureWorkerQEMU(ctx context.Context, original *os.File, initial unix.Stat_t) (result error) {
	if original == nil {
		return ErrInvalid
	}
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.review || r.daemon == nil || r.pid <= 1 {
		return ErrReviewRequired
	}
	defer func() {
		if result != nil {
			_, err := r.contain(result)
			result = errors.Join(result, err)
		}
	}()
	return r.observeCaptureWorkerLockedQEMU(ctx, original, initial)
}

// Internal only. Caller holds the original runtime gate; connection composition
// keeps client then runtime gates together across both worker/TCP fences.
func (r *serverObserverRuntimeQEMU) observeCaptureWorkerLockedQEMU(ctx context.Context, original *os.File, initial unix.Stat_t) (result error) {
	if original == nil {
		return ErrInvalid
	}
	if r.closed || r.review || r.daemon == nil || r.pid <= 1 {
		return ErrReviewRequired
	}
	observed, err := r.captureStatusLockedQEMU(ctx)
	if err != nil {
		return fmt.Errorf("capture STATUS observation: %w", err)
	}
	w := r.captureWorker
	if w == nil {
		fd, err := unix.Open("/proc/"+observed.server.PID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		w = &serverCaptureWorkerQEMU{proc: os.NewFile(uintptr(fd), "original-capture-server-worker"), status: observed}
		r.captureWorker = w
	} else if observed != w.status {
		return ErrMismatch
	}
	base := "/proc/self/fd/" + strconv.FormatUint(uint64(w.proc.Fd()), 10)
	before, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.pid)
	if err != nil || (w.start != "" && w.start != before) {
		return fmt.Errorf("capture worker original generation: %w", errors.Join(ErrMismatch, err))
	}
	pid, err := strconv.ParseUint(w.status.server.PID, 10, 31)
	if err != nil {
		return ErrMismatch
	}
	group, groupErr := unix.Getpgid(int(pid))
	actual, actualErr := os.Stat(base + "/exe")
	expected, expectedErr := r.code.code.files["usr/sbin/smbd"].Stat()
	var held, server unix.Stat_t
	if groupErr != nil || group != r.pid || actualErr != nil || expectedErr != nil || !os.SameFile(actual, expected) ||
		unix.Fstat(int(original.Fd()), &held) != nil || unix.Stat(base+"/root/shares/readonly/capture-read", &server) != nil ||
		!samePendingObjectQEMU(initial, held) || !samePendingObjectQEMU(initial, server) || uint64(held.Dev) != w.status.device || uint64(held.Ino) != w.status.inode {
		return fmt.Errorf("capture worker executable/group/local-object: %w", ErrMismatch)
	}
	var link [96]byte
	n, err := unix.Readlinkat(int(w.proc.Fd()), "fd/3", link[:])
	if err != nil || string(link[:n]) != fmt.Sprintf("socket:[%d]", r.channel.right.inode) {
		return fmt.Errorf("capture worker original endpoint: %w", ErrMismatch)
	}
	after, err := pendingWorkerStatQEMU(base, w.status.server.PID, r.pid)
	if err != nil || before != after {
		return errors.Join(ErrMismatch, err)
	}
	w.start = before
	return ctx.Err()
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

var pendingHealthyAttemptedQEMU atomic.Bool

// One fixed fixture per disposable process. Reviewed references remain strongly
// reachable until whole guest/process disposal; no finalizer-based release.
var pendingHealthyRetainedQEMU *pendingHealthyRetentionQEMU

type pendingHealthyRetentionQEMU struct {
	client  *pendingClientOwnerQEMU
	runtime *NativeSambaRuntimeQEMU
	file    *os.File
	server  *pendingServerOpenQEMU
}

// This healthy prerequisite retains actual server inputs, executes the real
// client once and performs CLOSE only. OPEN telemetry is NOT an independent
// original SMB server/session/open/object witness or permission to WRITE.
func (p *Plan) ProbeNativePendingClientQEMU(ctx context.Context, code, configuration, state *os.File, lookup fileserviceplan.SambaEnrollmentLookup, roots [2]*os.File) (result error) {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	if !pendingHealthyAttemptedQEMU.CompareAndSwap(false, true) {
		return ErrReviewRequired
	}
	retained := &pendingHealthyRetentionQEMU{}
	pendingHealthyRetainedQEMU = retained
	defer func() {
		if result != nil {
			if retained.client != nil {
				result = errors.Join(result, retained.client.stop(context.Background()))
			}
			if retained.runtime != nil {
				result = errors.Join(result, retained.runtime.StopNativeDaemonQEMU(context.Background()))
				retained.runtime.owner.review = true
			}
			return // Keep all authorities/file; never retry release in review.
		}
		if retained.file != nil {
			if err := retained.file.Close(); err != nil {
				result = errors.Join(ErrReviewRequired, err)
				return
			}
		}
		if retained.server != nil && retained.server.proc != nil {
			if err := retained.server.proc.Close(); err != nil {
				result = errors.Join(ErrReviewRequired, err)
				return // Never retry an uncertain close.
			}
		}
		pendingHealthyRetainedQEMU = nil
	}()
	clientPlan, bootstrapPlan, err := readPendingExpectedQEMU()
	if err != nil {
		return err
	}
	var callers []*os.File
	for _, name := range []string{"/run/phantowd-pending-client-input", "/run/phantowd-pending-client-bootstrap"} {
		fd, err := unix.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			for _, caller := range callers {
				err = errors.Join(err, caller.Close())
			}
			return err
		}
		callers = append(callers, os.NewFile(uintptr(fd), "healthy-pending-client-caller"))
	}
	secret := []byte("native-qemu-only-password-29") // Enrolled synthetic fixture only.
	client, err := newPendingClientOwnerQEMU(ctx, clientPlan, bootstrapPlan, callers[0], callers[1], secret)
	retained.client = client
	clear(secret)
	for _, caller := range callers {
		err = errors.Join(err, caller.Close())
	}
	if err != nil {
		return err // Reviewed authority belongs to whole disposable-guest teardown.
	}
	r, err := p.newNativeSambaRuntimeQEMU(ctx, code, configuration, state, lookup, &roots)
	retained.runtime = r
	if err != nil {
		return err
	}
	if err := r.prepareNativeDataAuthenticationQEMU(); err != nil {
		return err
	}
	r.daemonAttempted = true
	observed, err := r.owner.Start(ctx)
	if err != nil || observed.State != processowner.StateReady || len(observed.Processes.Members) != 1 {
		return errors.Join(ErrReviewRequired, err)
	}
	r.daemonPID = observed.Processes.Members[0].Process.PID
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	// Hold the original local object through the trusted share root. This
	// witnesses local continuity/unchanged bytes only, NOT the SMB open identity.
	fd, err := openBeneath(int(roots[1].Fd()), "pending-write", unix.O_RDONLY)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "healthy-original-synthetic-object")
	retained.file = file
	var initial unix.Stat_t
	if unix.Fstat(fd, &initial) != nil || initial.Mode != unix.S_IFREG|0600 || initial.Uid != 2001 || initial.Gid != 2001 || initial.Size != 4096 || initial.Nlink != 1 {
		return ErrMismatch
	}
	if err := verifyPendingBytesQEMU(file); err != nil {
		return err
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(client.start(canceled), context.Canceled) || client.started {
		return ErrMismatch
	}
	if err := client.start(ctx); err != nil {
		return fmt.Errorf("pending client start: %w", err)
	}
	if err := client.start(ctx); !errors.Is(err, ErrReviewRequired) {
		return ErrMismatch
	}
	if err := client.close(); !errors.Is(err, processowner.ErrBusy) {
		return ErrMismatch
	}
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return errors.Join(err, client.stop(context.Background()))
	}
	// Independent STATUS producer, original server worker and retained local
	// inode. Still NOT the remote socket/opaque client-handle/request binding.
	retained.server, err = r.observePendingServerOpenQEMU(ctx, file, initial)
	if err != nil {
		return fmt.Errorf("pending server open observation: %w", err)
	}
	if err := client.inputs.revalidate(ctx); err != nil {
		return err
	}
	if err := retained.server.recheckQEMU(ctx, file, initial); err != nil {
		return fmt.Errorf("pending original server open continuity: %w", err)
	}
	if err := client.closeClient(ctx); err != nil {
		return fmt.Errorf("pending client close: %w", err)
	}
	// Compare the local object through BOTH the retained descriptor and actual
	// server view, ignoring atime (a read is permitted) but preserving identity,
	// mode, ownership, nlink, size, mtime and ctime. No path-selected replacement.
	view := "/proc/" + strconv.Itoa(r.daemonPID) + "/root/shares/writable/pending-write"
	var retainedStat, server unix.Stat_t
	if unix.Fstat(fd, &retainedStat) != nil || unix.Stat(view, &server) != nil ||
		!samePendingObjectQEMU(initial, retainedStat) || !samePendingObjectQEMU(initial, server) {
		return ErrMismatch
	}
	if err := verifyPendingBytesQEMU(file); err != nil {
		return err
	}
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	if err := client.close(); err != nil {
		return err
	}
	if client.start(ctx) == nil || client.closeClient(ctx) == nil {
		return ErrMismatch
	}
	return r.Close(context.Background()) // Client settled before original server inputs release.
}

func samePendingObjectQEMU(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func verifyPendingBytesQEMU(file *os.File) error {
	if file == nil {
		return ErrInvalid
	}
	data := make([]byte, 4097)
	n, err := file.ReadAt(data, 0)
	if n != 4096 || err != io.EOF || !bytes.Equal(data[:4096], bytes.Repeat([]byte{0x3c}, 4096)) {
		return ErrMismatch
	}
	return nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Byte-count observation only. No recvmsg, ancillary import, metadata decode,
// record drain, sequence publication or recovery/admission authority.
func (p *pendingServerPacketQEMU) queuedBytesQEMU(ctx context.Context) (int, error) {
	if err := p.enter(ctx); err != nil {
		return 0, err
	}
	defer func() { <-p.gate }()
	if p.closed || p.closeTried || p.releaseTried || p.endpoints(true) != nil {
		return 0, ErrReviewRequired
	}
	n, err := unix.IoctlGetInt(int(p.receiver.Fd()), unix.SIOCINQ)
	if err != nil || (n != 0 && n != 88) || (n == 0 && !p.queueEmpty()) || (n == 88 && p.queueEmpty()) || p.endpoints(true) != nil {
		return 0, errors.Join(ErrMismatch, err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

func captureUncertainReadFixtureQEMU() bool {
	if serverObserverCodeGuardQEMU() != nil {
		return false
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return false
	}
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_uncertain_read_fixture=1" {
			return true
		}
	}
	return false
}

func captureUncertainReadProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t) error {
	if ctx == nil || o == nil || r == nil || original == nil || !captureUncertainReadFixtureQEMU() || o.capturePeer != r || r.channel == nil || r.channel.sequence != 0 {
		return ErrInvalid
	}
	if n, err := r.channel.queuedBytesQEMU(ctx); err != nil || n != 0 {
		return errors.Join(ErrMismatch, err)
	}
	if frame, err := o.readCaptureFrameQEMU(ctx); !errors.Is(err, ErrReviewRequired) || frame != (pendingServerPacketObservationQEMU{}) || !o.review || !r.review || r.channel.sequence != 0 {
		return errors.Join(ErrMismatch, err)
	}
	return captureQueuedReviewProofQEMU(ctx, o, r, original, initial)
}

// Post-containment fixture assertions shared by missing-ack and cancellation.
// Does not admit work, clear review, consume queued records or supply a backend.
func captureQueuedReviewProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t) error {
	if ctx == nil || o == nil || r == nil || original == nil || o.capturePeer != r || o.captureAdapter == nil || r.captureWorker == nil || r.channel == nil || !o.review || !r.review || r.channel.sequence != 0 {
		return ErrInvalid
	}
	if settled, err := o.captureAdapter.StoppedInReviewQEMU(ctx); err != nil || !settled {
		return errors.Join(ErrMismatch, err)
	}
	stopped, err := r.Stop(ctx)
	if !errors.Is(err, ErrReviewRequired) || stopped.State != processowner.StateReviewRequired || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		return errors.Join(ErrMismatch, err)
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	for range 2 {
		if n, err := r.channel.queuedBytesQEMU(ctx); err != nil || n != 88 || r.channel.sequence != 0 {
			return errors.Join(ErrMismatch, err)
		}
		if frame, err := o.readCaptureFrameQEMU(ctx); !errors.Is(err, ErrReviewRequired) || frame != (pendingServerPacketObservationQEMU{}) || r.channel.sequence != 0 {
			return ErrMismatch
		}
		if !errors.Is(o.start(ctx), ErrReviewRequired) || !errors.Is(o.close(), ErrReviewRequired) || !errors.Is(r.Close(), ErrReviewRequired) {
			return ErrMismatch
		}
		if _, err := r.Start(ctx); !errors.Is(err, ErrReviewRequired) {
			return ErrMismatch
		}
	}
	for _, files := range []map[string]*os.File{r.code.code.files, r.configuration.contents.files, r.state.files, o.inputs.client.files, o.inputs.bootstrap.files} {
		for _, pin := range files {
			if pin == nil {
				return ErrMismatch
			}
			if _, err := unix.FcntlInt(pin.Fd(), unix.F_GETFD, 0); err != nil {
				return err
			}
		}
	}
	for _, pin := range []*os.File{r.captureWorker.file, r.captureWorker.proc, r.proc, r.channel.sender, r.channel.receiver} {
		if pin == nil {
			return ErrMismatch
		}
		if _, err := unix.FcntlInt(pin.Fd(), unix.F_GETFD, 0); err != nil {
			return err
		}
	}
	var held unix.Stat_t
	if unix.Fstat(int(original.Fd()), &held) != nil || !samePendingObjectQEMU(initial, held) || unix.Fstat(int(r.captureWorker.file.Fd()), &held) != nil || !samePendingObjectQEMU(initial, held) {
		return ErrMismatch
	}
	if after, err := retainedFixtureFDCount(); err != nil || before != after {
		return errors.Join(ErrMismatch, err)
	}
	return ctx.Err()
}

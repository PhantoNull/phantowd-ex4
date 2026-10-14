//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Dedicated private composition, never an arbitrary PID/socket/backend input.
// Caller supplies only the already constructed original capture runtime and
// original synthetic object. Later checks accept no replacement authority.
func (o *pendingClientOwnerQEMU) bindCaptureConnectionQEMU(ctx context.Context, peer *serverObserverRuntimeQEMU, file *os.File, initial unix.Stat_t) error {
	return o.captureConnectionQEMU(ctx, peer, file, initial, true)
}

func (o *pendingClientOwnerQEMU) recheckCaptureConnectionQEMU(ctx context.Context) error {
	return o.captureConnectionQEMU(ctx, nil, nil, unix.Stat_t{}, false)
}

func (o *pendingClientOwnerQEMU) captureConnectionQEMU(ctx context.Context, peer *serverObserverRuntimeQEMU, file *os.File, initial unix.Stat_t, binding bool) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review || !o.started || o.settled || o.inputs == nil || o.captureAdapter == nil || o.adapter != nil || o.connectionPeer != nil {
		return ErrReviewRequired
	}
	if binding {
		if o.capturePeer != nil {
			return ErrReviewRequired
		}
	} else {
		peer, file, initial = o.capturePeer, o.connectionFile, o.connectionInitial
	}
	if peer == nil || file == nil {
		return o.fail(ErrInvalid)
	}
	// Fixed lock order: original client Owner -> original capture runtime.
	// The runtime never calls back into the client Owner. Busy/pre-canceled
	// admission acquires no peer reference and has no process effects.
	if err := peer.enter(ctx); err != nil {
		return err
	}
	defer func() { <-peer.gate }()
	if peer.closed || peer.review || peer.daemon == nil || peer.pid <= 1 {
		return o.fail(ErrReviewRequired)
	}
	if binding {
		o.capturePeer, o.connectionFile, o.connectionInitial = peer, file, initial
	}
	defer func() {
		if result != nil {
			_, peerErr := peer.contain(result)
			result = errors.Join(result, peerErr, o.fail(result))
		}
	}()
	if err := o.inputs.revalidate(ctx); err != nil {
		return err
	}
	if err := peer.observeCaptureWorkerLockedQEMU(ctx, file, initial); err != nil {
		return err
	}
	handle, err := o.captureAdapter.InitialHandleObservationQEMU(ctx)
	if err != nil || peer.captureWorker == nil || peer.captureWorker.status.session != strconv.FormatUint(handle.SessionID, 10) || peer.captureWorker.status.tree != strconv.FormatUint(uint64(handle.TreeID), 10) {
		return errors.Join(ErrMismatch, err)
	}
	if binding {
		if err := o.captureAdapter.BindConnectionQEMU(ctx, peer.captureWorker.proc); err != nil {
			return err
		}
	} else {
		if err := o.captureAdapter.RecheckConnectionQEMU(ctx); err != nil {
			return err
		}
	}
	if err := peer.observeCaptureWorkerLockedQEMU(ctx, file, initial); err != nil {
		return err
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

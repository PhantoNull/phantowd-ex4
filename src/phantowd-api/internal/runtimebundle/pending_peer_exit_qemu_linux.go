//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Stop ONLY the already owned daemon group after the real original binding.
// No fake peer, writable request, socket injection, retry or re-admission.
func (retained *pendingHealthyRetentionQEMU) qualifyPeerExitQEMU(ctx context.Context, initial unix.Stat_t) error {
	if ctx == nil || retained == nil || retained.client == nil || retained.runtime == nil || retained.server == nil || retained.file == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	client, r, peer := retained.client, retained.runtime, retained.server
	if client.review || client.adapter == nil || client.connectionPeer != peer || r.closed || r.owner.review {
		return ErrMismatch
	}
	if err := r.StopNativeDaemonQEMU(ctx); err != nil {
		return err // Uncertain stop cannot qualify this fixed fault.
	}
	if r.daemonPID != 0 || r.owner.snapshot.Processes.State != processowner.StateStopped {
		return ErrMismatch
	}
	// Exercise the concrete connection observation first, not merely its outer
	// already-dead server fence. It must quarantine and settle its owned client.
	if err := client.adapter.RecheckConnectionQEMU(ctx); !errors.Is(err, processowner.ErrReviewRequired) {
		return errors.Join(ErrMismatch, err)
	}
	if err := client.recheckConnection(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.Join(ErrMismatch, err)
	}
	r.owner.review = true // No server-input release or restart after this fault.
	if !client.review || !client.stopTried || client.settled || client.closed {
		return ErrMismatch
	}
	if err := client.adapter.VerifyConnectionReviewQEMU(ctx); err != nil {
		return err
	}
	// No CLOSE notice/control, refreshed peer or healthy release is permitted.
	if !errors.Is(client.closeClient(ctx), ErrReviewRequired) || !errors.Is(client.start(ctx), ErrReviewRequired) ||
		!errors.Is(client.bindConnection(ctx, peer, retained.file, initial), ErrReviewRequired) ||
		!errors.Is(client.close(), ErrReviewRequired) || !errors.Is(client.close(), ErrReviewRequired) {
		return ErrMismatch
	}
	if err := client.adapter.VerifyConnectionReviewQEMU(ctx); err != nil {
		return err
	}
	if client.connectionPeer != peer || r.closed || r.helper == nil || r.owner.closed || r.owner.root == nil || len(r.owner.files) == 0 {
		return ErrMismatch
	}
	if err := client.inputs.revalidate(ctx); err != nil {
		return err
	}
	files := []*os.File{retained.file, peer.proc, r.helper, r.owner.root}
	for _, file := range r.owner.files {
		files = append(files, file)
	}
	for _, file := range files {
		if file == nil {
			return ErrMismatch
		}
		if _, err := file.Stat(); err != nil {
			return err
		}
	}
	var final unix.Stat_t
	if unix.Fstat(int(retained.file.Fd()), &final) != nil || !samePendingObjectQEMU(initial, final) {
		return ErrMismatch
	}
	if err := verifyPendingBytesQEMU(retained.file); err != nil {
		return err
	}
	return ctx.Err()
}

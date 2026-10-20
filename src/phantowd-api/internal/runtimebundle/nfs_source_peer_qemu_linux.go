//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// One fixed additional fault after the existing source-loss proof. This is not
// a product control endpoint, a caller-selected PID/signal or automatic recovery.
func (o *NFSSourceAccessQEMU) InjectSourceMountdExitFixtureQEMU(ctx context.Context) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.daemonLoss || !nfsSourceAccessSelectorQEMU(true, true) || o.loss == nil || !o.loss.verified || !o.review || !o.consumed {
		return ErrInvalid
	}
	if o.loss.peerExitAttempted || o.loss.withdrawalAttempted {
		return ErrReviewRequired
	}
	if err := o.lease.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.lease.gate }()
	s, err := o.lease.parent.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	if !s.review || !s.sourceReserved || s.sourceAccess != o || o.lease.consumer != o || o.lease.closed || s.closed ||
		s.revalidateReferences(ctx) != nil || o.observeSourceLossConsumersQEMU(ctx) != nil {
		return ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o.loss.peerExitAttempted = true
	defer func() {
		if result != nil {
			o.loss.peerExitCause = result
		}
	}()
	if err := o.loss.companions[1].owner.InterruptNFSSourceMountdFixtureQEMU(ctx); err != nil {
		return err
	}
	if err := o.observeSourcePeerLossQEMU(ctx); err != nil {
		return err
	}
	o.loss.peerExitVerified = true
	return nil
}

func (o *NFSSourceAccessQEMU) observeSourcePeerLossQEMU(ctx context.Context) error {
	if o.loss == nil || !o.loss.peerExitAttempted || o.loss.withdrawalAttempted || !o.exportsLoaded || o.closed || o.settled ||
		!o.review || o.cause == nil || o.checkReferences(ctx) != nil || o.loss.kernel.CheckRunning(ctx) != nil {
		return ErrReviewRequired
	}
	if _, err := o.cachedClientReferencesQEMU(); err != nil {
		return err
	}
	mountd, rpcbind := o.loss.companions[1], o.loss.companions[0]
	state, err := mountd.owner.Observe(ctx)
	if !errors.Is(err, processowner.ErrReviewRequired) || state.State != processowner.StateReviewRequired || state.Generation != 1 || len(state.Members) != 1 ||
		state.Members[0].Process.PID != mountd.pid || state.Members[0].Process.DiagnosticsTruncated || !errors.Is(unix.Kill(-mountd.pid, 0), unix.ESRCH) ||
		mountd.owner.CheckNFSSourceMountdAccessHandoffQEMU(ctx, true) != nil {
		return errors.Join(ErrReviewRequired, err)
	}
	if inode, err := nfsRPCListenerQEMU(true); err != nil || inode != "" {
		return errors.Join(ErrMismatch, err)
	}
	state, err = rpcbind.owner.Observe(ctx)
	if err != nil || state.State != processowner.StateReady || state.Generation != 1 || len(state.Members) != 1 ||
		state.Members[0].Process.PID != rpcbind.pid || state.Members[0].Process.DiagnosticsTruncated || rpcbind.owner.CheckNFSRPCBindHandoffQEMU(ctx) != nil {
		return errors.Join(ErrMismatch, err)
	}
	if ok, err := nfsRPCNullQEMU(ctx, false); err != nil || !ok {
		return errors.Join(ErrMismatch, err)
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || !ok {
		return errors.Join(ErrMismatch, err)
	}
	return ctx.Err()
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Original access gate is held. This is owned compensation/observation ONLY,
// never normal admission or recovery. It deliberately does not depend on an
// injected-exit flag: original references, not a test event, authorize cleanup.
func (o *NFSSourceAccessQEMU) reviewedServerOperation(ctx context.Context, operation uint8) error {
	v := o.server
	if v != nil && (v.rpcOnlyStartRefused || v.kernelConstructionRefused) {
		return o.reviewedPartialStartOperation(ctx, operation)
	}
	if v.kernelBindReviewRouteQEMU() {
		return o.reviewedKernelBindOperationQEMU(ctx, operation)
	}
	if !o.review || o.cause == nil || o.closed || o.sourceLoss || o.daemonLoss || !o.consumed || o.settled || v == nil ||
		v.source != o || v.code == nil || v.kernel == nil || !v.mountd.valid() || !v.rpcbind.valid() ||
		!v.mountd.mountd || v.rpcbind.mountd || v.stopped || o.capture != nil || o.heldClient != nil || len(o.mounts) != 0 ||
		o.faultFile != nil || (operation != 3 && operation != 4) {
		return ErrReviewRequired
	}
	if operation == 3 && (!v.running || v.stopAttempted) || operation == 4 &&
		(v.running || !v.stopAttempted || !v.reviewStopVerified || v.reviewStopCause != nil) {
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
	if s != v.code || !s.review || s.cause == nil || s.closed || !s.sourceReserved || s.sourceAccess != o ||
		o.lease.consumer != o || o.lease.closed || v.mountd.code != s || v.rpcbind.code != s ||
		v.mountd.source != o || v.rpcbind.source != o || s.revalidateReferences(ctx) != nil || o.checkReferences(ctx) != nil {
		return ErrReviewRequired
	}
	if operation == 4 {
		return v.observeReviewedStopped(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.stopAttempted = true // Even uncertainty consumes this sole attempt.
	v.reviewStopCause = v.stopReviewed(ctx)
	if v.reviewStopCause != nil {
		fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SERVER_REVIEW_STOP_FAILURE phase=%s\n", v.phase)
		return errors.Join(ErrReviewRequired, v.reviewStopCause)
	}
	v.running = false
	v.reviewStopVerified = true
	// Verified absence is NOT a normal successful Stop. Preserve actual peer
	// failure and review, original authority and every remaining reference.
	return errors.Join(ErrReviewRequired, v.peerStopCause)
}

func (v *nfsServerQEMU) stopReviewed(ctx context.Context) error {
	o, s := v.source, v.code
	v.phase = "review-withdraw-exports"
	for _, role := range []processowner.NFSWithdrawalOperationQEMU{processowner.NFSWithdrawOwnedQEMU, processowner.NFSFlushOwnedQEMU} {
		if err := o.withdrawOwnedExportQEMU(ctx, s, role, true); err != nil {
			return err
		}
	}
	if _, count, err := v.observeTable(ctx); err != nil || count != 0 {
		return errors.Join(ErrMismatch, err)
	}
	o.exportsLoaded = false
	v.phase = "review-kernel-stop"
	if err := v.kernel.Stop(ctx); err != nil {
		return err
	}
	if err := v.kernel.CheckStopped(ctx); err != nil {
		return err
	}
	if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || ok {
		return errors.Join(ErrMismatch, err)
	}
	v.phase = "review-mountd-stop"
	v.peerStopCause = v.mountd.stop(ctx)
	if v.peerStopCause != nil {
		if !errors.Is(v.peerStopCause, ErrReviewRequired) {
			return v.peerStopCause
		}
		if err := v.mountd.checkReviewedStopped(ctx); err != nil {
			return errors.Join(v.peerStopCause, err)
		}
	} else if err := v.mountd.checkStopped(ctx); err != nil {
		return err
	}
	v.phase = "review-rpcbind-stop"
	if err := v.rpcbind.stop(ctx); err != nil {
		return err
	}
	if err := v.rpcbind.checkStopped(ctx); err != nil {
		return err
	}
	v.phase = "review-stopped-observation"
	return v.observeReviewedStopped(ctx)
}

func (d *nfsDaemonQEMU) checkReviewedStopped(ctx context.Context) error {
	if !d.valid() || ctx == nil || !d.mountd || d.source == nil || !d.review || d.cause == nil || !d.readyEvidence ||
		!d.stopAttempted || d.stopped || d.closed || d.pid <= 1 {
		return ErrReviewRequired
	}
	if err := d.child.CheckNFSServerMountdReviewStopQEMU(ctx); err != nil {
		return err
	}
	if !errors.Is(unix.Kill(-d.pid, 0), unix.ESRCH) {
		return ErrReviewRequired
	}
	if inode, err := nfsRPCListenerQEMU(true); err != nil || inode != "" {
		return errors.Join(ErrReviewRequired, err)
	}
	if err := d.handoff(ctx, true); err != nil {
		return err
	}
	return ctx.Err()
}

func (v *nfsServerQEMU) observeReviewedStopped(ctx context.Context) error {
	if !v.stopAttempted || v.reviewStopCause != nil {
		return ErrReviewRequired
	}
	if err := v.kernel.CheckStopped(ctx); err != nil {
		return err
	}
	if v.mountd.stopped {
		if err := v.mountd.checkStopped(ctx); err != nil {
			return err
		}
	} else if err := v.mountd.checkReviewedStopped(ctx); err != nil {
		return err
	}
	if err := v.rpcbind.checkStopped(ctx); err != nil {
		return err
	}
	return v.source.observeServerStopped(ctx, v.code, true)
}

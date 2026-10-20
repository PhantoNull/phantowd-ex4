//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

// Bookkeeping only. Actual original kernel pending/stopped witnesses and all
// original lease/code/source references must still be verified under their gates.
func (v *nfsServerQEMU) kernelBindReviewRouteQEMU() bool {
	return v != nil && (v.kernelBindStopped || !v.stopAttempted && v.kernelBindStartBoundaryQEMU())
}

func (v *nfsServerQEMU) kernelBindStartBoundaryQEMU() bool {
	return v != nil && v.source != nil && v.code != nil && v.source.server == v && v.code.sourceAccess == v.source &&
		!v.running && !v.stopped && !v.ioAttempted && !v.source.exportsLoaded &&
		!v.rpcOnlyStartRefused && !v.kernelConstructionRefused && v.kernelStartAttempted && v.kernel != nil &&
		v.ownsReadyPartialDaemon(v.rpcbind, false) && v.ownsReadyPartialDaemon(v.mountd, true)
}

// Original access gate held. No selector or errno from a caller grants cleanup.
// First settle only the original never-attached socket; only a fresh original
// witness then admits reverse-order settlement of the two acquired daemons.
func (o *NFSSourceAccessQEMU) reviewedKernelBindOperationQEMU(ctx context.Context, operation uint8) error {
	v := o.server
	if !o.review || o.cause == nil || o.closed || o.settled || !o.consumed || o.sourceLoss || o.daemonLoss ||
		!v.kernelBindStartBoundaryQEMU() || o.capture != nil || o.heldClient != nil || o.faultFile != nil || len(o.mounts) != 0 ||
		(operation != 3 && operation != 4) {
		return ErrReviewRequired
	}
	if operation == 3 && (v.stopAttempted || v.kernelBindStopped || v.rpcbind.stopAttempted || v.mountd.stopAttempted || v.rpcbind.stopped || v.mountd.stopped) ||
		operation == 4 && (!v.reviewStopVerified || v.reviewStopCause != nil || !v.kernelBindStopped || !v.partialStartStoppedProof()) {
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
		o.lease.consumer != o || o.lease.closed || s.revalidateReferences(ctx) != nil || o.checkReferences(ctx) != nil {
		return ErrReviewRequired
	}
	if operation == 4 {
		return v.observeKernelBindStoppedQEMU(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.stopAttempted = true // Uncertainty in classification/close/Wait cannot retry.
	v.reviewStopCause = v.kernel.CheckUnattachedPendingQEMU(ctx)
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, v.reviewStopCause)
	}
	stopErr := v.kernel.Stop(ctx)
	if !errors.Is(stopErr, nfskernel.ErrRefused) || ctx.Err() != nil {
		v.reviewStopCause = errors.Join(ErrReviewRequired, stopErr, ctx.Err())
		return v.reviewStopCause
	}
	v.reviewStopCause = v.kernel.CheckUnattachedStoppedQEMU(ctx)
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, stopErr, v.reviewStopCause)
	}
	v.kernelBindStopped = true
	for _, daemon := range [2]*nfsDaemonQEMU{v.mountd, v.rpcbind} {
		v.reviewStopCause = daemon.stop(ctx)
		if v.reviewStopCause == nil {
			v.reviewStopCause = daemon.checkStopped(ctx)
		}
		if v.reviewStopCause != nil {
			return errors.Join(ErrReviewRequired, stopErr, v.reviewStopCause)
		}
	}
	v.reviewStopCause = v.observeKernelBindStoppedQEMU(ctx)
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, stopErr, v.reviewStopCause)
	}
	v.reviewStopVerified = true
	return errors.Join(ErrReviewRequired, stopErr) // Keep the actual reviewed kernel cause.
}

func (v *nfsServerQEMU) observeKernelBindStoppedQEMU(ctx context.Context) error {
	if !v.kernelBindStopped || !v.stopAttempted || v.reviewStopCause != nil || !v.partialStartStoppedProof() {
		return ErrReviewRequired
	}
	if err := v.kernel.CheckUnattachedStoppedQEMU(ctx); err != nil {
		return err
	}
	for _, daemon := range [2]*nfsDaemonQEMU{v.mountd, v.rpcbind} {
		if err := daemon.checkStopped(ctx); err != nil {
			return err
		}
	}
	return v.source.observeServerStopped(ctx, v.code, true)
}

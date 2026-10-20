//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"context"
	"errors"
	"strings"
)

// KernelReadyCancelSelectorQEMU selects only an explicit disposable guest.
// It grants neither compensation nor kernel control authority.
func KernelReadyCancelSelectorQEMU(command []byte) (selected, valid bool) {
	if len(command) > 4096 || strings.IndexByte(string(command), 0) >= 0 {
		return false, false
	}
	code, source, inits, bad := 0, 0, 0, false
	for _, word := range strings.FieldsFunc(string(command), func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		if strings.HasPrefix(word, "init=") {
			inits++
			selected = selected || word == "init=/usr/sbin/phantowd-nfs-kernel-ready-cancel-init"
		}
		switch word {
		case "phantowd_nfs_code_fixture=1":
			code++
		case "phantowd_nfs_source_fixture=1":
			source++
		default:
			bad = bad || strings.HasPrefix(word, "phantowd_nfs_")
		}
	}
	if !selected {
		return false, true
	}
	return true, code == 1 && source == 1 && inits == 1 && !bad
}

// Bookkeeping only: independent checks of original references and the live
// original controller below are mandatory. Successful Start, not an injected
// cancellation, distinguishes this from a failed, never-attached listener.
func (v *nfsServerQEMU) kernelReadyReviewRouteQEMU() bool {
	return v != nil && (v.kernelReadyStopped || !v.stopAttempted && v.kernelReadyStartBoundaryQEMU())
}

func (v *nfsServerQEMU) kernelReadyStartBoundaryQEMU() bool {
	return v != nil && v.source != nil && v.code != nil && v.source.server == v && v.code.sourceAccess == v.source &&
		!v.running && !v.stopped && !v.ioAttempted && !v.source.exportsLoaded &&
		!v.rpcOnlyStartRefused && !v.kernelConstructionRefused && v.kernelStartAttempted && v.kernelStartVerified &&
		!v.kernelBindStopped && v.kernel != nil && v.ownsReadyPartialDaemon(v.rpcbind, false) && v.ownsReadyPartialDaemon(v.mountd, true)
}

// One original access gate and one independent Owner cleanup budget cover this
// operation. Never withdraw/activate exports at this no-export frontier, close
// the original controller or release references. Uncertainty consumes the attempt.
func (o *NFSSourceAccessQEMU) reviewedKernelReadyOperationQEMU(ctx context.Context, operation uint8) error {
	v := o.server
	if !o.review || o.cause == nil || o.closed || o.settled || !o.consumed || o.sourceLoss || o.daemonLoss ||
		!v.kernelReadyStartBoundaryQEMU() || o.capture != nil || o.heldClient != nil || o.faultFile != nil || len(o.mounts) != 0 ||
		(operation != 3 && operation != 4) {
		return ErrReviewRequired
	}
	if operation == 3 && (v.stopAttempted || v.kernelReadyStopped || v.rpcbind.stopAttempted || v.mountd.stopAttempted || v.rpcbind.stopped || v.mountd.stopped) ||
		operation == 4 && (!v.reviewStopVerified || v.reviewStopCause != nil || !v.kernelReadyStopped || !v.partialStartStoppedProof()) {
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
		return v.observeKernelReadyStoppedQEMU(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.stopAttempted = true
	v.reviewStopCause = v.kernel.CheckRunning(ctx)
	if v.reviewStopCause == nil {
		v.reviewStopCause = v.kernel.Stop(ctx)
	}
	if v.reviewStopCause == nil {
		v.reviewStopCause = v.kernel.CheckStopped(ctx)
	}
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, v.reviewStopCause)
	}
	v.kernelReadyStopped = true
	for _, daemon := range [2]*nfsDaemonQEMU{v.mountd, v.rpcbind} {
		v.reviewStopCause = daemon.stop(ctx)
		if v.reviewStopCause == nil {
			v.reviewStopCause = daemon.checkStopped(ctx)
		}
		if v.reviewStopCause != nil {
			return errors.Join(ErrReviewRequired, v.reviewStopCause)
		}
	}
	v.reviewStopCause = v.observeKernelReadyStoppedQEMU(ctx)
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, v.reviewStopCause)
	}
	v.reviewStopVerified = true
	return ErrReviewRequired // Stopped originals do not clear the original cause.
}

func (v *nfsServerQEMU) observeKernelReadyStoppedQEMU(ctx context.Context) error {
	if !v.kernelReadyStopped || !v.stopAttempted || v.reviewStopCause != nil || !v.partialStartStoppedProof() {
		return ErrReviewRequired
	}
	if err := v.kernel.CheckStopped(ctx); err != nil {
		return err
	}
	for _, daemon := range [2]*nfsDaemonQEMU{v.mountd, v.rpcbind} {
		if err := daemon.checkStopped(ctx); err != nil {
			return err
		}
	}
	return v.source.observeServerStopped(ctx, v.code, true)
}

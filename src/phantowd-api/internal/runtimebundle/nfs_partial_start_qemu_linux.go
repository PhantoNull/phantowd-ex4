//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"context"
	"errors"
	"strings"
)

// Fixed synthetic constructor refusal only; never cleanup authority. Cleanup
// must derive its boundary from original resources, not this test selector.
func nfsRPCOnlyFailureSelectorQEMU(command []byte) bool {
	if len(command) > 4096 {
		return false
	}
	required := []string{"phantowd_nfs_code_fixture=", "phantowd_nfs_source_fixture=", "phantowd_nfs_source_owner_rpc_start_failure_fixture="}
	counts := [3]int{}
	for _, word := range strings.Fields(string(command)) {
		for index, prefix := range required {
			if strings.HasPrefix(word, prefix) {
				if word != prefix+"1" {
					return false
				}
				counts[index]++
			}
		}
		for _, prefix := range []string{"phantowd_nfs_source_loss_fixture=", "phantowd_nfs_source_daemon_loss_fixture=", "phantowd_nfs_source_owner_policy_loss_fixture=", "phantowd_nfs_source_owner_daemon_loss_fixture=", "phantowd_nfs_source_owner_stop_loss_fixture="} {
			if strings.HasPrefix(word, prefix) {
				return false
			}
		}
	}
	return counts == [3]int{1, 1, 1}
}

// Bookkeeping boundary only, not authority or stopped proof. In particular,
// never accept a non-nil failed constructor result or an uncertain RPC child.
func (v *nfsServerQEMU) rpcOnlyStartBoundary() bool {
	if v == nil || !v.rpcOnlyStartRefused || v.source == nil || v.code == nil ||
		v.source.server != v || v.code.sourceAccess != v.source || v.running || v.stopped || v.ioAttempted ||
		v.source.exportsLoaded || v.mountd != nil || v.kernel != nil || !v.rpcbind.valid() {
		return false
	}
	d := v.rpcbind
	return d.code == v.code && d.source == v.source && !d.mountd && d.attempted && d.readyEvidence &&
		d.pid > 1 && !d.review && !d.closed
}

// Original access gate is held. Only the actually acquired RPC child is
// stopped; no mountd, NFSD, export mutation or reference release is invented.
func (o *NFSSourceAccessQEMU) reviewedRPCOnlyOperation(ctx context.Context, operation uint8) error {
	v := o.server
	if !o.review || o.cause == nil || o.closed || o.settled || !o.consumed || o.sourceLoss || o.daemonLoss ||
		!v.rpcOnlyStartBoundary() || o.capture != nil || o.heldClient != nil || o.faultFile != nil || len(o.mounts) != 0 ||
		(operation != 3 && operation != 4) {
		return ErrReviewRequired
	}
	if operation == 3 && v.stopAttempted || operation == 4 &&
		(!v.stopAttempted || !v.reviewStopVerified || v.reviewStopCause != nil || !v.rpcbind.stopped || !v.rpcbind.stoppedProof) {
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
		if err := v.rpcbind.checkStopped(ctx); err != nil {
			return err
		}
		return o.observeServerStopped(ctx, s, true)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.stopAttempted = true // One admitted compensation; uncertainty cannot retry.
	v.reviewStopCause = v.rpcbind.stop(ctx)
	if v.reviewStopCause == nil {
		v.reviewStopCause = v.rpcbind.checkStopped(ctx)
	}
	if v.reviewStopCause == nil {
		v.reviewStopCause = o.observeServerStopped(ctx, s, true)
	}
	if v.reviewStopCause != nil {
		return errors.Join(ErrReviewRequired, v.reviewStopCause)
	}
	v.reviewStopVerified = true
	return ErrReviewRequired // Physical absence never becomes healthy admission.
}

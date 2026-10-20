//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Independent graceful exit of this original server's mountd. The caller must
// not run supervision concurrently with this test-only mutation; its original
// Owner enforces that exclusion. This method never marks a successful injection as
// detected by supervision, and never starts, retries, stops or releases peers.
func (o *NFSSourceAccessQEMU) InjectServerMountdExitFixtureQEMU(ctx context.Context) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.closed || o.review || o.sourceLoss || o.daemonLoss || !o.consumed || o.settled || o.server == nil ||
		!o.server.running || o.server.stopped || o.server.stopAttempted || o.server.peerExitAttempted {
		return ErrInvalid
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
	v := o.server
	if o.lease.consumer != o || s.sourceAccess != o || v.source != o || v.code != s || v.mountd == nil ||
		o.lease.revalidate(ctx, s) != nil || o.check(ctx) != nil || v.check(ctx) != nil {
		return ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.peerExitAttempted = true
	defer func() {
		if result != nil {
			o.review = true
			if o.cause == nil {
				o.cause = result
			}
		}
	}()
	if err := v.mountd.child.InterruptNFSServerMountdFixtureQEMU(ctx); err != nil {
		return err
	}
	if !errors.Is(unix.Kill(-v.mountd.pid, 0), unix.ESRCH) {
		return ErrReviewRequired
	}
	if inode, err := nfsRPCListenerQEMU(true); err != nil || inode != "" {
		return errors.Join(ErrReviewRequired, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.peerExitVerified = true
	return nil
}

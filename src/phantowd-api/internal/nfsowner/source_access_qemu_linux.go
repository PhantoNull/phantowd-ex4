//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// RunAccessFixtureQEMU is a finite synthetic-guest campaign, not product startup.
func (o *SourceRuntimeQEMU) RunAccessFixtureQEMU(ctx context.Context) error {
	return o.runAccessFixtureQEMU(ctx, false, false)
}

// ProbeSourceLossFixtureQEMU reports only success of an intentional fault test.
// The join MUST remain in review afterwards, with live consumers retained.
func (o *SourceRuntimeQEMU) ProbeSourceLossFixtureQEMU(ctx context.Context) error {
	return o.runAccessFixtureQEMU(ctx, true, false)
}

func (o *SourceRuntimeQEMU) ProbeSourceDaemonLossFixtureQEMU(ctx context.Context) error {
	return o.runAccessFixtureQEMU(ctx, true, true)
}

func (o *SourceRuntimeQEMU) InjectSourceMountdExitFixtureQEMU(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.review || o.access == nil || o.accessVolume == nil || o.accessSettled {
		return ErrInvalid
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if s.runtime != o || s.closed || s.closeUncertain {
		return ErrReviewRequired
	}
	return o.access.InjectSourceMountdExitFixtureQEMU(ctx)
}

// Finite fixture cleanup only; successful test return NEVER clears review.
func (o *SourceRuntimeQEMU) WithdrawSourceLossFixtureQEMU(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.review || o.access == nil || o.accessVolume == nil || o.accessSettled {
		return ErrInvalid
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if s.runtime != o || s.closed || s.closeUncertain {
		return ErrReviewRequired
	}
	return o.access.WithdrawSourceLossFixtureQEMU(ctx)
}

func (o *SourceRuntimeQEMU) runAccessFixtureQEMU(ctx context.Context, sourceLoss, daemonLoss bool) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed || o.accessAttempted {
		return ErrState
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if err := o.verify(ctx, s); err != nil {
		return err
	}
	if len(s.roots) != 3 {
		return ErrInvalid
	}
	var sources [4]*os.File
	for i, root := range s.roots {
		sources[i] = root.file
	}
	o.accessAttempted = true
	if len(s.pins) != 1 {
		return o.fail(ErrInvalid)
	}
	o.accessVolume, err = s.pins[0].OpenDirectory(".")
	if err != nil {
		return o.fail(err)
	}
	sources[3] = o.accessVolume
	if daemonLoss {
		o.access, err = runtimebundle.NewNFSSourceDaemonLossAccessQEMU(ctx, o.lease, sources)
	} else if sourceLoss {
		o.access, err = runtimebundle.NewNFSSourceLossAccessQEMU(ctx, o.lease, sources)
	} else {
		o.access, err = runtimebundle.NewNFSSourceAccessQEMU(ctx, o.lease, sources)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_ACCESS_FAILURE phase=constructor")
		return o.fail(err)
	}
	var runErr error
	if sourceLoss {
		runErr = o.access.Run(ctx)
	} else {
		runErr = func() error {
			owner, err := newSourceServerOwnerQEMU(o, s)
			if err != nil {
				return err
			}
			preCanceled, cancelStart := context.WithCancel(ctx)
			cancelStart()
			if !errors.Is(owner.Start(preCanceled), context.Canceled) || !errors.Is(o.access.CheckServerStoppedFixtureQEMU(preCanceled), context.Canceled) {
				return ErrInvalid
			}
			if err := owner.Start(ctx); err != nil {
				return err
			}
			copyOwner := *owner
			if copyOwner.Start(ctx) == nil || copyOwner.Check(ctx) == nil || copyOwner.Stop(ctx) == nil || copyOwner.Close(ctx) == nil ||
				!errors.Is(owner.Start(ctx), ErrState) {
				return ErrInvalid
			}
			copyAccess := *o.access
			if copyAccess.StartServerFixtureQEMU(ctx) == nil || copyAccess.CheckServerFixtureQEMU(ctx) == nil ||
				copyAccess.ExerciseServerIOFixtureQEMU(ctx) == nil || copyAccess.StopServerFixtureQEMU(ctx) == nil ||
				copyAccess.CheckServerStoppedFixtureQEMU(ctx) == nil || o.access.CheckServerStoppedFixtureQEMU(ctx) == nil ||
				o.access.StartServerFixtureQEMU(ctx) == nil || o.access.Close(ctx) == nil {
				return ErrInvalid
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if !errors.Is(o.access.CheckServerFixtureQEMU(canceled), context.Canceled) ||
				!errors.Is(o.access.StopServerFixtureQEMU(canceled), context.Canceled) {
				return ErrInvalid
			}
			if err := owner.Check(ctx); err != nil {
				return err
			}
			if err := o.access.ExerciseServerIOFixtureQEMU(ctx); err != nil {
				return err
			}
			if err := owner.Check(ctx); err != nil {
				return err
			}
			if err := stopSourceServerThroughSupervisionQEMU(ctx, owner); err != nil {
				return err
			}
			if o.access.StopServerFixtureQEMU(ctx) == nil || o.access.CheckServerFixtureQEMU(ctx) == nil || o.access.ExerciseServerIOFixtureQEMU(ctx) == nil {
				return ErrInvalid
			}
			return owner.Close(ctx)
		}()
	}
	if sourceLoss {
		if !errors.Is(runErr, runtimebundle.ErrReviewRequired) {
			return o.fail(errors.Join(ErrInvalid, runErr))
		}
		_ = o.fail(runErr) // Preserve ORIGINAL failure even if the test succeeds.
		return o.access.VerifySourceLossRetainedQEMU(ctx)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_ACCESS_FAILURE phase=run")
		return o.fail(runErr)
	}
	if !o.accessSettled || o.accessVolume != nil {
		return o.fail(ErrReviewRequired)
	}
	if !sourceLoss {
		fmt.Println("PHANTOWD_NFS_SOURCE_SERVER_READY split_calls=true original_policy_identity=true original_daemons=true kernel_verified=true exports_verified=true owner_ready_checks=2 copied_refused=true early_close_refused=true pre_cancel_unchanged=true start_once=true stop_once=true io=true stopped=true original_parents_retained=true product=false scope=qemu-only")
		fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_READY fixed_backend=true original_claims=true real_start_check_stop=true idle_cancel=true exclusive=true close_after_stop=true no_restart=true periodic_real_check=false product=false scope=qemu-only")
	}
	return o.verify(ctx, s)
}

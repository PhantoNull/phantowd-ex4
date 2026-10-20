//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func parseOwnerDaemonLossSelector(data []byte) (selected, valid bool) {
	return parseOwnerLossSelector(data, "phantowd_nfs_source_owner_daemon_loss_fixture=")
}

// Explicit independent exit BEFORE supervision, so mutation cannot contend
// with a scheduled check's join/runtime gates. Only the scheduled scan may
// detect it; historical Observe is not a fresh daemon observation.
func runSourceOwnerDaemonLoss(ctx context.Context, joined *nfsowner.SourceRuntimeQEMU, authority *sourcePolicyFixture,
	roots *nfsowner.ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU, lease *mountowner.MountedVolumeSetLease) (result error) {
	phase := "owner-construction"
	defer func() {
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_OWNER_DAEMON_LOSS_FAILURE phase=%s\n", phase)
		}
	}()
	owner, err := joined.NewServerOwnerFixtureQEMU(ctx)
	if err != nil {
		return err
	}
	phase = "owner-start"
	if err := owner.Start(ctx); err != nil {
		return err
	}
	phase = "source-io"
	if err := owner.ExerciseSourceIOFixtureQEMU(ctx); err != nil {
		return err
	}
	phase = "independent-mountd-exit"
	if err := owner.InjectSourceMountdExitFixtureQEMU(ctx); err != nil {
		return err
	}
	state, err := owner.Observe()
	if err != nil || state != nfsowner.Running {
		return errors.New("injection falsely represented as supervised detection")
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_ARMED real_io=true original_mountd_exit=true fault_before_supervision=true historical_owner_running=true detection=false product=false scope=qemu-only")
	phase = "scheduled-detection"
	err = owner.Supervise(ctx, time.Second)
	if !errors.Is(err, nfsowner.ErrReviewRequired) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errors.New("scheduled mountd refusal not observed"), err)
	}
	phase = "stopped-retained"
	if err := joined.VerifyServerStoppedRetainedFixtureQEMU(ctx); err != nil {
		return errors.Join(errors.New("reviewed original server stop not verified"), err)
	}
	retained, err := sourceFDCount()
	if err != nil {
		return err
	}
	state, err = owner.Observe()
	if err != nil || state != nfsowner.ReviewRequired {
		return errors.New("original owner lost review")
	}
	for _, operation := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close, owner.ExerciseSourceIOFixtureQEMU, owner.InjectSourceMountdExitFixtureQEMU,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if !errors.Is(operation(ctx), nfsowner.ErrReviewRequired) {
			return errors.New("review admitted retry/restart/release")
		}
	}
	phase = "retained-original-authority"
	if !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
		!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs.Close(), processowner.ErrBusy) ||
		!errors.Is(lease.Close(), mountowner.ErrBusy) || !errors.Is(authority.policyOwner.Close(), naspolicystore.ErrBusy) ||
		!errors.Is(authority.identity.Close(), identityowner.ErrBusy) || authority.policy.Verify(ctx) != nil ||
		authority.identityRef.Verify(ctx) != nil || !errors.Is(inputs.Check(ctx), runtimebundle.ErrReviewRequired) ||
		joined.VerifyServerStoppedRetainedFixtureQEMU(ctx) != nil {
		return errors.New("review lost original authority or stopped witness")
	}
	if after, err := sourceFDCount(); err != nil || after != retained {
		return errors.New("review released original references")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_READY scheduled_detection=true manual_detection=false original_mountd_exit=true kernel_stopped=true daemons_stopped=true exports_withdrawn=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false quiescence=false product=false scope=qemu-only")
	return nil
}

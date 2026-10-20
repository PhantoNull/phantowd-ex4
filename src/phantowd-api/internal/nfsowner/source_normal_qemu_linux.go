//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
)

// The finite normal campaign now uses the same original per-operation adapter.
func (o *SourceRuntimeQEMU) runNormalServerFixtureQEMU(ctx context.Context) error {
	owner, err := o.NewServerOwnerFixtureQEMU(ctx)
	if err != nil {
		return err
	}
	copySource := *o
	if got, err := copySource.NewServerOwnerFixtureQEMU(ctx); got != nil || !errors.Is(err, ErrInvalid) {
		return ErrInvalid
	}
	if got, err := o.NewServerOwnerFixtureQEMU(ctx); got != nil || !errors.Is(err, ErrState) {
		return ErrInvalid
	}
	if !errors.Is(o.Close(), ErrBusy) || o.Check(ctx) != nil {
		return ErrInvalid
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
		copyOwner.ExerciseSourceIOFixtureQEMU(ctx) == nil || !errors.Is(owner.Start(ctx), ErrState) {
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
		!errors.Is(o.access.StopServerFixtureQEMU(canceled), context.Canceled) || !errors.Is(owner.ExerciseSourceIOFixtureQEMU(canceled), context.Canceled) {
		return ErrInvalid
	}
	if err := owner.Check(ctx); err != nil {
		return err
	}
	if err := owner.ExerciseSourceIOFixtureQEMU(ctx); err != nil {
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
	if err := owner.Close(ctx); err != nil {
		return err
	}
	if err := o.Check(ctx); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_SERVER_READY split_calls=true original_policy_identity=true original_daemons=true kernel_verified=true exports_verified=true owner_ready_checks=2 copied_refused=true early_close_refused=true pre_cancel_unchanged=true start_once=true stop_once=true io=true stopped=true original_parents_retained=true product=false scope=qemu-only")
	fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_READY fixed_backend=true original_claims=true real_start_check_stop=true idle_cancel=true exclusive=true close_after_stop=true no_restart=true periodic_real_check=false product=false scope=qemu-only")
	return nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

const plannedSupervisionMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY same_authorities=true complete_scan=true serialized=true cancellation_stopped=true originals_retained=true restart_refused=true close_before_release=true stopped_reaped=true no_fd_leak=true activation=false scope=qemu-only"

// Exercise the already-running service after its ORIGINAL access proof. No
// replacement backend, roster, policy or authority is introduced. Cancellation
// is deliberately after a complete scan; mid-worker/fault traces stay separate.
func qualifyPlannedSupervisionQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	initial, err := service.Status()
	if err != nil || initial.State != "ready" || !initial.DataVerified || !initial.IdentityRetained || !initial.SharesRetained || initial.RuntimeClosed {
		return errors.New("planned supervision lacks original live access authority")
	}
	canceled, cancelBefore := context.WithCancel(ctx)
	cancelBefore()
	if err := service.Supervise(canceled, time.Second); !errors.Is(err, context.Canceled) {
		return errors.New("planned supervision admitted pre-canceled request")
	}
	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()
	completed := make(chan error, 1)
	go func() { completed <- service.Supervise(loopCtx, time.Second) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			return errors.Join(errors.New("planned supervision ended before complete scan"), err)
		case <-ctx.Done():
			cancelLoop()
			return errors.Join(ctx.Err(), <-completed)
		case <-ticker.C:
			status, err := service.Status()
			if err != nil {
				cancelLoop()
				return errors.Join(err, <-completed)
			}
			if status.Checks <= initial.Checks {
				continue
			}
			// Status is telemetry, never an admission token. The supervisor owns
			// the exclusive gate even between scans; none of these may compete.
			for _, operation := range []func(context.Context) error{service.Observe, service.Start, service.VerifyDataAccess, service.Close} {
				if err := operation(ctx); !errors.Is(err, processowner.ErrBusy) {
					cancelLoop()
					return errors.Join(errors.New("planned supervision lost exclusive lifecycle"), err, <-completed)
				}
			}
			if err := service.Supervise(ctx, time.Second); !errors.Is(err, processowner.ErrBusy) {
				cancelLoop()
				return errors.Join(errors.New("planned supervisor admitted a second loop"), err, <-completed)
			}
			cancelLoop()
			if err := <-completed; !errors.Is(err, context.Canceled) || errors.Is(err, runtimebundle.ErrReviewRequired) {
				return errors.Join(errors.New("planned accepted cancellation did not settle stop"), err)
			}
			status, err = service.Status()
			if err != nil || status.State != "stopped" || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed || !status.DataVerified {
				return errors.New("planned supervision released originals before runtime closure")
			}
			if !errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
				return errors.New("planned stopped supervision lost original authorities")
			}
			for _, operation := range []func(context.Context) error{service.Start, service.Observe, service.VerifyDataAccess} {
				if err := operation(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
					return errors.New("planned stopped service resumed without new admission")
				}
			}
			if err := service.Supervise(ctx, time.Second); !errors.Is(err, runtimebundle.ErrReviewRequired) {
				return errors.New("planned stopped service resumed supervision")
			}
			return nil // The caller must still explicitly close runtime, then originals.
		}
	}
}

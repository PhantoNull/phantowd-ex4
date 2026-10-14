//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

const plannedHeldCloseMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_HELD_CLOSE_READY same_authorities=true same_daemon=true data_verified=true original_session=true exclusive_supervision=true accepted_cancellation=true client_daemon_stopped=true private_inputs=15 originals_retained=true old_observers_refused=true runtime_close_before_release=true repeated_close=true closed_refused=true no_fd_leak=true activation=false scope=qemu-only"

// A normal-path qualification, separate from the sticky-review source fault.
// The original service has already proved data access. Its fixed granted holder
// must stay bound to the SAME backend session and both authorities through the
// complete supervised scan. Accepted cancellation stops, but does not release;
// only a subsequent verified full Close may release the original authorities.
func qualifyPlannedHeldCancellationQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, native *runtimebundle.NativeSambaRuntimeQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := service.StartHeldSessionQEMU(canceled); !errors.Is(err, context.Canceled) {
		return errors.New("planned held close accepted canceled admission")
	}
	if err := service.StartHeldSessionQEMU(ctx); err != nil {
		return err
	}
	if err := service.StartHeldSessionQEMU(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("planned held close accepted duplicate admission")
	}
	live, err := observePlannedHeldFaultStopQEMU(ctx, native)
	if err != nil || live.DaemonStopped || live.ClientStopped || !live.InputsRetained {
		return errors.Join(errors.New("planned live holder supplied stopped or released evidence"), err)
	}
	// This uses the accepted exclusive loop unchanged, including the original
	// session witness in every serialized storage-first/identity verification.
	if err := qualifyPlannedSupervisionQEMU(ctx, service, owner, handoff); err != nil {
		return err
	}
	for range 2 {
		stopped, err := observePlannedHeldFaultStopQEMU(ctx, native)
		if err != nil || !stopped.DaemonStopped || !stopped.ClientStopped || !stopped.InputsRetained {
			return errors.Join(errors.New("planned cancellation lacks complete retained group stop"), err)
		}
	}
	status, err := service.Status()
	if err != nil || status.State != "stopped" || !status.DataVerified || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed ||
		!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
		return errors.New("planned held stop released original authority")
	}
	for range 2 {
		if err := service.Close(ctx); err != nil {
			return err
		}
		status, err = service.Status()
		if err != nil || status.State != "stopped" || !status.DataVerified || status.IdentityRetained || status.SharesRetained || !status.RuntimeClosed {
			return errors.New("planned held close released authority before runtime closure")
		}
		// The old observers still cannot certify the larger group; after Close
		// neither they nor the held observer may claim retained-input evidence.
		observed, err := observePlannedHeldFaultStopQEMU(ctx, native)
		if observed != (runtimebundle.PlannedHeldStopObservationQEMU{}) || !errors.Is(err, runtimebundle.ErrReviewRequired) {
			return errors.New("closed held runtime supplied retained-input evidence")
		}
	}
	return nil
}

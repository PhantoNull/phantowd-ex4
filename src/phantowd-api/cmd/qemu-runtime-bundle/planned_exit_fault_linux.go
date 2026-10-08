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

const plannedExitFaultMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_EXIT_FAULT_READY same_authorities=true same_daemon=true data_verified=true original_handle=true single_use=true exclusive_supervision=true review_sticky=true stopped_reaped=true private_inputs=15 capture_retained=true capture_before_worker=true runtime_inputs_retained=true originals_busy=true restart_refused=true normal_stop_refused=true private_mount_namespace=true subprocess_disposal=true parent_fd_equal=true activation=false scope=qemu-only"

const plannedExitFaultChildProofQEMU = "PHANTOWD_PLANNED_EXIT_FAULT_CHILD_READY same_authorities=true same_daemon=true data_verified=true original_handle=true single_use=true exclusive_supervision=true review_sticky=true stopped_reaped=true private_inputs=15 capture_retained=true capture_before_worker=true runtime_inputs_retained=true originals_busy=true restart_refused=true normal_stop_refused=true private_mount_namespace=true scope=qemu-subprocess-only\n"

func nativePlannedExitFaultSubprocessQEMU() error {
	return nativePlannedFaultSubprocessQEMU("exit")
}

func nativePlannedExitFaultQEMU() error {
	return nativePlannedFaultQEMU("exit")
}

func qualifyPlannedExitFaultQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, native *runtimebundle.NativeSambaRuntimeQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	initial, err := service.Status()
	if err != nil || initial.State != "ready" || !initial.DataVerified || !initial.IdentityRetained || !initial.SharesRetained || initial.RuntimeClosed {
		return errors.New("planned exit fault lacks original live access authority")
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
			return errors.Join(errors.New("planned exit supervisor ended before complete scan"), err)
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
			if err := service.Observe(ctx); !errors.Is(err, processowner.ErrBusy) {
				cancelLoop()
				return errors.Join(errors.New("planned exit supervisor lost exclusivity"), err, <-completed)
			}
			canceled, cancelRequest := context.WithCancel(ctx)
			cancelRequest()
			if err := native.RequestPlannedDaemonExitQEMU(canceled); !errors.Is(err, context.Canceled) {
				cancelLoop()
				return errors.Join(errors.New("planned exit accepted canceled request"), err, <-completed)
			}
			// No caller PID/path/program/group is accepted. This fault requests
			// exit through the ORIGINAL owned Process; it is not a Stop witness.
			if err := native.RequestPlannedDaemonExitQEMU(ctx); err != nil {
				cancelLoop()
				return errors.Join(errors.New("planned original-handle exit refused"), err, <-completed)
			}
			if !errors.Is(native.RequestPlannedDaemonExitQEMU(ctx), runtimebundle.ErrReviewRequired) {
				cancelLoop()
				return errors.Join(errors.New("planned exit request repeated"), <-completed)
			}
			select {
			case err := <-completed:
				if !errors.Is(err, runtimebundle.ErrReviewRequired) {
					return errors.Join(errors.New("planned unexpected exit did not quarantine supervisor"), err)
				}
			case <-ctx.Done():
				cancelLoop()
				return errors.Join(ctx.Err(), <-completed)
			}
			for range 2 {
				stopped, err := native.ObservePlannedReviewStopQEMU(ctx)
				status, statusErr := service.Status()
				if err != nil || !stopped.GroupStopped || !stopped.InputsRetained || !stopped.CaptureRetained || !stopped.BeforeWorker || statusErr != nil ||
					status.State != "review-required" || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed ||
					!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
					return errors.Join(errors.New("planned exit lost reviewed stop or retained authority"), err, statusErr)
				}
				if normal, err := native.ObservePlannedStopQEMU(ctx); normal != (runtimebundle.PlannedStopObservationQEMU{}) || !errors.Is(err, runtimebundle.ErrReviewRequired) {
					return errors.New("planned exit was reclassified as normal stop")
				}
			}
			for _, operation := range []func(context.Context) error{service.Start, service.Observe, service.VerifyDataAccess, service.Close, native.RequestPlannedDaemonExitQEMU} {
				if !errors.Is(operation(ctx), runtimebundle.ErrReviewRequired) {
					return errors.New("planned exit revived operation or released authority")
				}
			}
			if !errors.Is(service.Supervise(ctx, time.Second), runtimebundle.ErrReviewRequired) {
				return errors.New("planned exit revived supervision")
			}
			stopped, err := native.ObservePlannedReviewStopQEMU(ctx)
			status, statusErr := service.Status()
			if err != nil || !stopped.GroupStopped || !stopped.InputsRetained || !stopped.CaptureRetained || !stopped.BeforeWorker || statusErr != nil || status.State != "review-required" ||
				!status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed ||
				!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
				return errors.Join(errors.New("planned exit nonrevival lost retained originals"), err, statusErr)
			}
			return nil // Only verified child disposal follows; no product recovery.
		}
	}
}

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

const plannedOpenFileMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_OPEN_FILE_READY same_authorities=true same_daemon=true data_verified=true original_object=true original_open=true exclusive_supervision=true accepted_cancellation=true client_daemon_stopped=true private_inputs=15 original_file_retained=true originals_busy=true old_observers_refused=true runtime_close_before_release=true repeated_close=true closed_refused=true no_fd_leak=true activation=false scope=qemu-only"

// Actual opening in a separate fresh guest; no idle IPC$ proof is relabeled.
func qualifyPlannedOpenFileQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, native *runtimebundle.NativeSambaRuntimeQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := service.StartHeldOpenFileQEMU(canceled); !errors.Is(err, context.Canceled) {
		return errors.New("planned file accepted canceled admission")
	}
	if err := service.StartHeldOpenFileQEMU(ctx); err != nil {
		return err
	}
	if !errors.Is(service.StartHeldOpenFileQEMU(ctx), runtimebundle.ErrReviewRequired) ||
		!errors.Is(service.StartHeldSessionQEMU(ctx), runtimebundle.ErrReviewRequired) {
		return errors.New("planned file accepted second or replacement holder")
	}
	live, err := observePlannedOpenFileStopQEMU(ctx, native)
	retained, retainErr := service.ObserveOriginalOpenFileRetainedQEMU(ctx)
	if err != nil || retainErr != nil || live.DaemonStopped || live.ClientStopped || !live.InputsRetained || !retained {
		return errors.Join(errors.New("planned file lacks live original retention"), err, retainErr)
	}
	// Start already verified the original object/open and both authorities
	// after client readiness. The next independent complete recheck belongs
	// to the exclusive supervisor, not a duplicate fixture Observe that
	// consumes its fixed action budget before the cycle begins.
	if err := qualifyPlannedSupervisionQEMU(ctx, service, owner, handoff); err != nil {
		return err
	}
	for range 2 {
		stopped, err := observePlannedOpenFileStopQEMU(ctx, native)
		retained, retainErr := service.ObserveOriginalOpenFileRetainedQEMU(ctx)
		if err != nil || retainErr != nil || !stopped.DaemonStopped || !stopped.ClientStopped || !stopped.InputsRetained || !retained {
			return errors.Join(errors.New("planned file stop lacks groups and original object"), err, retainErr)
		}
		if !errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
			return errors.New("planned file stop released original authorities")
		}
	}
	for range 2 {
		if err := service.Close(ctx); err != nil {
			return err
		}
		status, err := service.Status()
		if err != nil || status.State != "stopped" || !status.RuntimeClosed || status.IdentityRetained || status.SharesRetained {
			return errors.New("planned file close released before runtime settlement")
		}
		if retained, err := service.ObserveOriginalOpenFileRetainedQEMU(ctx); retained || !errors.Is(err, runtimebundle.ErrReviewRequired) {
			return errors.New("closed service supplied original file retention")
		}
		if observed, err := observePlannedOpenFileStopQEMU(ctx, native); observed != (runtimebundle.PlannedHeldStopObservationQEMU{}) || !errors.Is(err, runtimebundle.ErrReviewRequired) {
			return errors.New("closed runtime supplied file group retention")
		}
	}
	return nil
}

func observePlannedOpenFileStopQEMU(ctx context.Context, native *runtimebundle.NativeSambaRuntimeQEMU) (runtimebundle.PlannedHeldStopObservationQEMU, error) {
	for _, operation := range []func() error{
		func() error { _, err := native.ObserveNativeStopQEMU(ctx); return err },
		func() error { _, err := native.ObservePlannedStopQEMU(ctx); return err },
		func() error { _, err := native.ObservePlannedReviewStopQEMU(ctx); return err },
		func() error { _, err := native.ObservePlannedHeldStopQEMU(ctx); return err },
	} {
		if !errors.Is(operation(), runtimebundle.ErrReviewRequired) {
			return runtimebundle.PlannedHeldStopObservationQEMU{}, errors.New("older observer certified file holder")
		}
	}
	return native.ObservePlannedFileStopQEMU(ctx)
}

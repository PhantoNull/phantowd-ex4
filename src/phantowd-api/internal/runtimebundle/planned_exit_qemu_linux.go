//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// RequestPlannedDaemonExitQEMU is a fixed single-use disposable guest fault,
// not a service Stop or recovery operation. No caller chooses a process or
// signal. The existing owner must observe exit and verify whole-group teardown.
func (r *NativeSambaRuntimeQEMU) RequestPlannedDaemonExitQEMU(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.plannedExitAttempted || !r.plannedDataPrepared || !r.daemonAttempted ||
		r.daemonPID <= 1 || r.pending != nil || r.clients == nil || r.clientsAttempted ||
		r.owner.processes == nil || r.owner.serviceConfiguration == nil {
		return ErrReviewRequired
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	clients, err := r.clients.Observe(ctx)
	if err != nil || clients.State != processowner.StateStopped || clients.Generation != 0 || len(clients.Members) != 2 {
		return errors.Join(ErrReviewRequired, err)
	}
	for index, name := range []string{"qpmanaged", "qpsecond"} {
		client := clients.Members[index]
		if client.Name != name || client.Process.State != processowner.StateStopped || client.Process.Generation != 0 || client.Process.PID != 0 {
			return ErrReviewRequired
		}
	}
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	attempted, err := r.owner.processes.RequestNativeDataExitQEMU(ctx)
	if attempted {
		r.plannedExitAttempted = true // An uncertain admitted signal cannot retry.
	}
	if err != nil {
		if attempted {
			r.owner.review = true
		}
		return errors.Join(ErrReviewRequired, err)
	}
	// Success is signal admission only. No fabricated review, Stop, Wait,
	// group absence or release: those are independently qualified by the guest.
	return nil
}

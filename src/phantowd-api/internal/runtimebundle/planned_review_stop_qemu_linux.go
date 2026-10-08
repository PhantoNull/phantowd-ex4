//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

type PlannedReviewStopObservationQEMU struct {
	GroupStopped, InputsRetained  bool
	CaptureRetained, BeforeWorker bool
}

// ObservePlannedReviewStopQEMU observes the fixed planned data lifetime only
// after review and verified whole-group teardown. It deliberately does not
// replace ObservePlannedStopQEMU's strict normal-state contract. The retained
// original daemon group number is checked for absence, never signaled/adopted;
// reuse or uncertainty refuses. No stop/close retry, release or recovery occurs.
func (r *NativeSambaRuntimeQEMU) ObservePlannedReviewStopQEMU(ctx context.Context) (PlannedReviewStopObservationQEMU, error) {
	if err := r.enter(ctx); err != nil {
		return PlannedReviewStopObservationQEMU{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || !r.plannedDataPrepared || !r.daemonAttempted || !r.owner.review || r.daemonPID <= 1 ||
		r.clients == nil || r.clientsAttempted || r.owner.processes == nil || r.owner.serviceConfiguration == nil {
		return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
	}
	// An exited daemon can refuse admission AFTER the credential worker's
	// inputs have been duplicated. Retain that capture, but accept it only
	// when it was never consumed and has no live child/group. An executed,
	// uncertain or closed capture still refuses. No Close or cleanup retry.
	beforeWorker := false
	if r.pending != nil {
		unconsumed, err := r.pending.UnconsumedQEMU(ctx)
		if err != nil || !unconsumed {
			return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
		}
		settled, err := r.pending.Settled(ctx)
		if err != nil || !settled {
			return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
		}
		beforeWorker = true
	}
	daemon, err := r.owner.processes.ObserveNativeDataReviewStopQEMU(ctx)
	if err != nil || !daemon.GroupStopped || !daemon.InputsRetained || unix.Kill(-r.daemonPID, 0) != unix.ESRCH {
		return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
	}
	clients, err := r.clients.Observe(ctx)
	if err != nil || clients.State != processowner.StateStopped || clients.Generation != 0 || len(clients.Members) != 2 {
		return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
	}
	for index, name := range []string{"qpmanaged", "qpsecond"} {
		client := clients.Members[index]
		if client.Name != name || client.Process.State != processowner.StateStopped || client.Process.Generation != 0 || client.Process.PID != 0 {
			return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
		}
	}
	// Retention only: no source-path reopening, content re-admission or claim
	// that the original storage/identity/configuration is still healthy.
	open := func(file *os.File) bool {
		if file == nil {
			return false
		}
		_, err := file.Stat()
		return err == nil
	}
	code, management, service, state := r.owner.retainedCode, r.owner.configuration, r.owner.serviceConfiguration, r.owner.sambaState
	if code == nil || management == nil || management.contents == nil || service.contents == nil || state == nil ||
		!open(r.helper) || !open(state.root) || len(state.files) != len(sambaStateDirectories) {
		return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
	}
	for _, tree := range []*retainedCode{code, management.contents, service.contents} {
		if !open(tree.root) || tree.plan == nil || len(tree.plan.files) == 0 || len(tree.files) != len(tree.plan.files) {
			return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
		}
		for _, expected := range tree.plan.files {
			if !open(tree.files[expected.Path]) {
				return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
			}
		}
	}
	for _, name := range sambaStateDirectories {
		if !open(state.files[name]) {
			return PlannedReviewStopObservationQEMU{}, ErrReviewRequired
		}
	}
	if err := ctx.Err(); err != nil {
		return PlannedReviewStopObservationQEMU{}, err
	}
	return PlannedReviewStopObservationQEMU{GroupStopped: true, InputsRetained: true,
		CaptureRetained: r.pending != nil, BeforeWorker: beforeWorker}, nil
}

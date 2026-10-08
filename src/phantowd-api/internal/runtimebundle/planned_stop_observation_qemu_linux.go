//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

type PlannedStopObservationQEMU struct {
	DaemonStopped, InputsRetained bool
}

// ObservePlannedStopQEMU is a separate read-only observation for the fixed
// planned data role, whose preconstructed held clients must never have started.
// The older native observer's two-client contract is unchanged. No signal,
// capture, close, release, source readmission, retry or recovery is performed.
// Open pins prove retention,
// not the continued validity of their contents or of the containing authorities.
func (r *NativeSambaRuntimeQEMU) ObservePlannedStopQEMU(ctx context.Context) (PlannedStopObservationQEMU, error) {
	if err := r.enter(ctx); err != nil {
		return PlannedStopObservationQEMU{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || !r.plannedDataPrepared || !r.daemonAttempted || r.clients == nil ||
		r.clientsAttempted || r.pending != nil || r.owner.processes == nil || r.owner.serviceConfiguration == nil {
		return PlannedStopObservationQEMU{}, ErrReviewRequired
	}
	daemon, err := r.owner.processes.ObserveNativeDataStopQEMU(ctx)
	if err != nil {
		return PlannedStopObservationQEMU{}, err
	}
	clients, err := r.clients.Observe(ctx)
	if err != nil {
		return PlannedStopObservationQEMU{}, err
	}
	if clients.State != processowner.StateStopped || clients.Generation != 0 || len(clients.Members) != 2 {
		return PlannedStopObservationQEMU{}, ErrReviewRequired
	}
	for index, name := range []string{"qpmanaged", "qpsecond"} {
		client := clients.Members[index]
		if client.Name != name || client.Process.State != processowner.StateStopped || client.Process.Generation != 0 || client.Process.PID != 0 {
			return PlannedStopObservationQEMU{}, ErrReviewRequired
		}
	}
	observed := PlannedStopObservationQEMU{
		DaemonStopped: r.daemonPID == 0 && daemon.Stopped,
	}
	open := func(file *os.File) bool {
		if file == nil {
			return false
		}
		_, err := file.Stat()
		return err == nil
	}
	code, management, service, state := r.owner.retainedCode, r.owner.configuration, r.owner.serviceConfiguration, r.owner.sambaState
	if code == nil || management == nil || management.contents == nil || service.contents == nil || state == nil {
		return PlannedStopObservationQEMU{}, ErrReviewRequired
	}
	observed.InputsRetained = daemon.InputsRetained && open(r.helper) && open(state.root)
	for _, tree := range []*retainedCode{code, management.contents, service.contents} {
		observed.InputsRetained = observed.InputsRetained && open(tree.root)
		if tree.plan == nil || len(tree.plan.files) == 0 || len(tree.files) != len(tree.plan.files) {
			observed.InputsRetained = false
			continue
		}
		for _, expected := range tree.plan.files {
			observed.InputsRetained = observed.InputsRetained && open(tree.files[expected.Path])
		}
	}
	if len(state.files) != len(sambaStateDirectories) {
		observed.InputsRetained = false
	}
	for _, name := range sambaStateDirectories {
		observed.InputsRetained = observed.InputsRetained && open(state.files[name])
	}
	if err := ctx.Err(); err != nil {
		return PlannedStopObservationQEMU{}, err
	}
	return observed, nil
}

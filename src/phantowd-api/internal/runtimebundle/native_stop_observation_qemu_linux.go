//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

type NativeStopObservationQEMU struct {
	DaemonStopped, ClientsStopped, CaptureSettled, CaptureRetained, InputsRetained bool
	BeforeWorker                                                                   bool
}

// Separate redacted observation after uncertain stop; never signals, retries
// close, releases pins, clears review or supplies product recovery authority.
// Process snapshots can say stopped only after their owned group is verified
// absent and reaped. Capture settlement alone does NOT prove it never executed.
func (r *NativeSambaRuntimeQEMU) ObserveNativeStopQEMU(ctx context.Context) (NativeStopObservationQEMU, error) {
	if err := r.enter(ctx); err != nil {
		return NativeStopObservationQEMU{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || !r.daemonAttempted || r.owner.processes == nil || r.clients == nil || r.plannedClientAttempted {
		return NativeStopObservationQEMU{}, ErrReviewRequired
	}
	daemon, err := r.owner.processes.Observe(ctx)
	if err != nil {
		return NativeStopObservationQEMU{}, err
	}
	clients, err := r.clients.Observe(ctx)
	if err != nil {
		return NativeStopObservationQEMU{}, err
	}
	stopped := func(set processowner.SetSnapshot, count int) bool {
		if set.State != processowner.StateStopped || len(set.Members) != count {
			return false
		}
		for _, member := range set.Members {
			if member.Process.State != processowner.StateStopped || member.Process.PID != 0 {
				return false
			}
		}
		return true
	}
	observed := NativeStopObservationQEMU{
		DaemonStopped:  r.daemonPID == 0 && stopped(daemon, 1),
		ClientsStopped: stopped(clients, 2), CaptureRetained: r.pending != nil,
	}
	if r.pending != nil {
		observed.CaptureSettled, err = r.pending.Settled(ctx)
		if err != nil {
			return NativeStopObservationQEMU{}, err
		}
		observed.BeforeWorker, err = r.pending.UnconsumedQEMU(ctx)
		if err != nil {
			return NativeStopObservationQEMU{}, err
		}
	}
	open := func(file *os.File) bool {
		if file == nil {
			return false
		}
		_, err := file.Stat()
		return err == nil
	}
	code, config, state := r.owner.retainedCode, r.owner.configuration, r.owner.sambaState
	if code == nil || config == nil || config.contents == nil || state == nil {
		return observed, nil
	}
	observed.InputsRetained = open(r.helper) && open(code.root) && open(config.contents.root) && open(state.root)
	for _, group := range []map[string]*os.File{code.files, config.contents.files, state.files} {
		if len(group) == 0 {
			observed.InputsRetained = false
		}
		for _, file := range group {
			observed.InputsRetained = observed.InputsRetained && open(file)
		}
	}
	if err := ctx.Err(); err != nil {
		return NativeStopObservationQEMU{}, err
	}
	return observed, nil
}

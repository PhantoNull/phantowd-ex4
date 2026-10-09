//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed authorized IPC$ holder, distinct from the older two-account fixture.
// The containing coordinator must verify its original storage/identity on both
// sides and prove the actual complete session inventory, outside this gate.
func (r *NativeSambaRuntimeQEMU) StartPlannedClientQEMU(ctx context.Context) (result error) {
	return r.startPlannedClientQEMU(ctx, false)
}

// Separate fixed file holder; the coordinator must retain/match the actual
// original object and recheck complete original storage/identity authority.
func (r *NativeSambaRuntimeQEMU) StartPlannedFileClientQEMU(ctx context.Context) error {
	return r.startPlannedClientQEMU(ctx, true)
}

func (r *NativeSambaRuntimeQEMU) startPlannedClientQEMU(ctx context.Context, file bool) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || !r.plannedDataPrepared || !r.plannedDataAttempted ||
		r.owner.serviceConfiguration == nil || r.daemonPID <= 1 || r.clientsAttempted || r.plannedClientAttempted {
		return ErrReviewRequired
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	r.plannedClientAttempted = true
	r.plannedFileClient = file
	defer func() {
		if result != nil {
			r.owner.review = true
			result = errors.Join(result, r.stopNativeDaemonQEMU())
		}
	}()
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	spec := processowner.MemberSpec{Name: "planned-qpsecond", Process: processowner.Spec{
		Executable: sambaFixtureHelper, Args: []string{"native-session", "qpsecond"},
		RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready: func(ctx context.Context) (bool, error) {
			authenticated, denied, err := r.nativeClientQEMU(ctx, "qpsecond", false)
			if denied {
				return false, ErrMismatch
			}
			return authenticated, err
		},
		ReadyTimeout: 4 * time.Second, ProbeInterval: 100 * time.Millisecond, StopTimeout: time.Second,
	}}
	if file {
		spec.Name = "planned-file-qpsecond"
		spec.Process.Args = []string{"native-file-session"}
		spec.Process.Ready = r.plannedFileClientReadyQEMU
	}
	var err error
	r.plannedClient, err = processowner.NewPinnedSet([]processowner.MemberSpec{spec}, []*os.File{r.helper})
	if err != nil {
		return err
	}
	started, err := r.plannedClient.Start(ctx)
	if err != nil {
		// Start owns its rollback. An uncertain result is not permission to
		// retry settlement; retain the set and still stop the daemon once.
		r.plannedClientStopAttempted, r.plannedClientStopErr = true, err
		return errors.Join(ErrReviewRequired, err)
	}
	if started.State != processowner.StateReady || len(started.Members) != 1 || started.Members[0].Process.PID <= 1 {
		return ErrReviewRequired
	}
	r.plannedClientPID = started.Members[0].Process.PID
	return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
}

func (r *NativeSambaRuntimeQEMU) stopPlannedClientQEMU() error {
	if r.plannedClient == nil {
		return nil
	}
	if r.plannedClientStopAttempted {
		return r.plannedClientStopErr
	}
	r.plannedClientStopAttempted = true
	stopped, err := r.plannedClient.Stop(context.Background())
	if err != nil || stopped.State != processowner.StateStopped || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		r.owner.review = true
		r.plannedClientStopErr = errors.Join(ErrReviewRequired, err)
	}
	return r.plannedClientStopErr
}

type PlannedHeldStopObservationQEMU struct {
	DaemonStopped, ClientStopped, InputsRetained bool
}

// No signals, worker execution, release, source readmission or stop retry.
// The unused two-client inventory remains required unchanged; this separate
// observer additionally proves the actually started single holder's settlement.
func (r *NativeSambaRuntimeQEMU) ObservePlannedHeldStopQEMU(ctx context.Context) (PlannedHeldStopObservationQEMU, error) {
	return r.observePlannedClientStopQEMU(ctx, false)
}

func (r *NativeSambaRuntimeQEMU) ObservePlannedFileStopQEMU(ctx context.Context) (PlannedHeldStopObservationQEMU, error) {
	return r.observePlannedClientStopQEMU(ctx, true)
}

func (r *NativeSambaRuntimeQEMU) observePlannedClientStopQEMU(ctx context.Context, file bool) (PlannedHeldStopObservationQEMU, error) {
	if err := r.enter(ctx); err != nil {
		return PlannedHeldStopObservationQEMU{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || !r.plannedClientAttempted || r.plannedFileClient != file || r.plannedClient == nil || r.plannedClientPID <= 1 || r.plannedClientStopErr != nil {
		return PlannedHeldStopObservationQEMU{}, ErrReviewRequired
	}
	base, err := r.observePlannedStopQEMU(ctx)
	if err != nil {
		return PlannedHeldStopObservationQEMU{}, err
	}
	client, err := r.plannedClient.Observe(ctx)
	name := "planned-qpsecond"
	if file {
		name = "planned-file-qpsecond"
	}
	if err != nil || client.Generation != 1 || len(client.Members) != 1 || client.Members[0].Name != name {
		return PlannedHeldStopObservationQEMU{}, errors.Join(ErrReviewRequired, err)
	}
	member := client.Members[0].Process
	stopped := r.plannedClientStopAttempted && client.State == processowner.StateStopped && member.State == processowner.StateStopped && member.PID == 0 && member.Generation == 1
	if stopped && unix.Kill(-r.plannedClientPID, 0) != unix.ESRCH {
		return PlannedHeldStopObservationQEMU{}, ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return PlannedHeldStopObservationQEMU{}, err
	}
	return PlannedHeldStopObservationQEMU{DaemonStopped: base.DaemonStopped, ClientStopped: stopped, InputsRetained: base.InputsRetained}, nil
}

// This bounded availability probe is NOT a file/session/object witness. The
// containing coordinator independently applies its complete strict parser and
// original-object binding after Start. Only a complete empty producer inventory
// permits waiting for the same single client; failures never retry or reopen.
func (r *NativeSambaRuntimeQEMU) plannedFileClientReadyQEMU(ctx context.Context) (bool, error) {
	output, err := r.executeQEMU(ctx, processowner.NativeSambaStatusQEMU, "", nil)
	defer clear(output)
	if err != nil {
		return false, err
	}
	var status struct {
		Version string                     `json:"version"`
		Files   map[string]json.RawMessage `json:"open_files"`
	}
	if len(output) == 0 || len(output) > 1<<20 || json.Unmarshal(output, &status) != nil || status.Version != "4.22.11" || status.Files == nil || len(status.Files) > 1 {
		return false, ErrMismatch
	}
	if len(status.Files) == 0 {
		return false, nil
	}
	_, expected := status.Files["/shares/writable/created"]
	if !expected {
		return false, ErrMismatch
	}
	return true, nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Constructed only inside the guarded native runtime; no caller selects client
// users, arguments, executable, input stream or privilege profile. Fresh-login
// readiness is separate from the controller's mandatory held-session inventory.
func (r *NativeSambaRuntimeQEMU) prepareNativeClientsQEMU() error {
	var specs []processowner.MemberSpec
	for _, name := range []string{"qpmanaged", "qpsecond"} {
		specs = append(specs, processowner.MemberSpec{Name: name, Process: processowner.Spec{
			Executable: sambaFixtureHelper, Args: []string{"native-session", name},
			RunAs: &processowner.Credentials{UID: 0, GID: 0},
			Ready: func(ctx context.Context) (bool, error) {
				authenticated, denied, err := r.nativeClientQEMU(ctx, name, false)
				if denied {
					return false, ErrMismatch
				}
				return authenticated, err
			},
			ReadyTimeout: 4 * time.Second, ProbeInterval: 100 * time.Millisecond, StopTimeout: time.Second,
		}})
	}
	var err error
	r.clients, err = processowner.NewPinnedSet(specs, []*os.File{r.helper, r.helper})
	return err
}

func (r *NativeSambaRuntimeQEMU) StartNativeClientsQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonPID == 0 || r.clients == nil || r.clientsAttempted {
		return ErrReviewRequired
	}
	r.clientsAttempted = true
	defer func() {
		if result != nil {
			r.owner.review = true
			result = errors.Join(result, r.stopNativeDaemonQEMU())
		}
	}()
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	started, err := r.clients.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Members) != 2 {
		return errors.Join(ErrReviewRequired, err)
	}
	return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
}

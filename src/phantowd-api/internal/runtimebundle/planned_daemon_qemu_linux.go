//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// StartPlannedDaemonQEMU admits only the previously prepared fixed service role
// and original two-share process tuple. The trusted containing coordinator must
// retain/freshly recompile complete storage and identity outside this gate on
// both sides. No callbacks, new backend, path or process profile are accepted.
// Legacy start APIs remain blocked; this is disposable QEMU, not product apply.
func (r *NativeSambaRuntimeQEMU) StartPlannedDaemonQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonAttempted || r.clientsAttempted ||
		!r.plannedDataPrepared || r.owner.serviceConfiguration == nil {
		return ErrReviewRequired
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	r.daemonAttempted = true
	defer func() {
		if result != nil {
			r.owner.review = true
			result = errors.Join(result, r.stopNativeDaemonQEMU())
		}
	}()
	// Fixed synthetic test credential, never an operator credential. The child
	// sees only a validated root-only tmpfs auth FD; no argv/env password.
	const auth = "/run/native-qpsecond-good.auth"
	file, err := os.OpenFile(auth, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	r.authPaths = append(r.authPaths, auth)
	_, err = file.WriteString("username = qpsecond\npassword = native-qemu-only-password-29\n")
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	started, err := r.owner.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("planned native daemon readiness"), err)
	}
	r.daemonPID = started.Processes.Members[0].Process.PID
	return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
}

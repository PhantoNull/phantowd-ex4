//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"golang.org/x/sys/unix"
)

func nativeStatusSourceDiagnosticFlagQEMU(commandLine []byte) (bool, error) {
	const flag = "phantowd_samba_status_source_diagnostic"
	found := false
	for _, field := range strings.Fields(string(commandLine)) {
		if field == flag || strings.HasPrefix(field, flag+"=") {
			if found || field != flag+"=1" {
				return false, errors.New("invalid status-source diagnostic flag")
			}
			found = true
		}
	}
	return found, nil
}

// Explicit optional diagnostic, not part of the normal/native union. The only
// mutation creates a NEW directory at one missing TDB pathname in this fresh
// guest's tmpfs. No existing file is overwritten, removed, restored or retried.
func nativeStatusSourceDiagnosticQEMU(parent context.Context, worker *runtimebundle.NativeSambaRuntimeQEMU) error {
	if parent == nil || parent.Err() != nil || worker == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("status-source diagnostic authority unavailable")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	commandLine, flagErr := os.ReadFile("/proc/cmdline")
	enabled, parseErr := nativeStatusSourceDiagnosticFlagQEMU(commandLine)
	var fs unix.Statfs_t
	const lock = "/run/phantowd-native-samba-state/lock"
	if err != nil || string(model) != "ARM Versatile PB\x00" || flagErr != nil || parseErr != nil || !enabled ||
		unix.Statfs(lock, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("status-source diagnostic requires guarded disposable guest")
	}
	const obstruction = lock + "/smbXsrv_session_global.tdb"
	if _, err := os.Lstat(obstruction); !errors.Is(err, os.ErrNotExist) {
		return errors.New("status-source diagnostic target already exists or is uncertain")
	}
	if err := os.Mkdir(obstruction, 0700); err != nil {
		return err
	}
	// Separate fixed status observation after successful preparation; the
	// original campaign parent still bounds it. No expired preparation handoff.
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	output, runErr := worker.ExecuteQEMU(ctx, processowner.NativeSambaSessionsQEMU, "", nil)
	defer clear(output)
	if runErr != nil && runtimebundle.NativeStatusDiagnosticsRefusedQEMU(runErr) &&
		errors.Is(runErr, runtimebundle.ErrReviewRequired) && ctx.Err() == nil && len(output) == 0 {
		// A fresh uncanceled context proves review, not the first deadline,
		// refuses another call. No second worker may be launched or retried.
		second, secondErr := worker.ExecuteQEMU(context.Background(), processowner.NativeSambaSessionsQEMU, "", nil)
		defer clear(second)
		if len(second) != 0 || !errors.Is(secondErr, runtimebundle.ErrReviewRequired) {
			return errors.New("status-source diagnostic lost sticky review")
		}
		failure, err := worker.ObserveNativeWorkerFailureQEMU(context.Background())
		if err != nil || !failure.Present || failure.Phase != "result" || failure.Reason != "mismatch" {
			return errors.New("status-source diagnostic lost original failure")
		}
		closeErr := worker.Close(context.Background())
		retired, observationErr := worker.ObserveNativeRetirementQEMU(context.Background())
		if !retired || observationErr != nil || !errors.Is(closeErr, runtimebundle.ErrReviewRequired) {
			return errors.Join(errors.New("status-source diagnostic retirement not confirmed with review"), closeErr, observationErr)
		}
		return nil // Review acknowledged separately from positively verified retirement.
	}
	if runErr == nil && smbexec.EmptyNativeStatusDiagnosticQEMU(output) {
		fmt.Println("PHANTOWD_DIAG_NATIVE_STATUS_SOURCE source_open_obstructed=true zero_exit=true parsed_empty=true output_accepted=true qualifying=false scope=qemu-only")
		return errors.New("status-source diagnostic observed accepted empty inventory after source-open failure")
	}
	return errors.New("status-source diagnostic did not establish the required refusal")
}

const nativeStatusSourceRefusalMarkerQEMU = "PHANTOWD_SAMBA_OWNER_NATIVE_STATUS_SOURCE_REFUSAL_READY source_open_obstructed=true zero_exit=true one_handoff=true unexpected_stderr_refused=true review_retained=true retry_refused=true stopped_reaped=true no_fd_leak=true producer_complete=false scope=qemu-only"

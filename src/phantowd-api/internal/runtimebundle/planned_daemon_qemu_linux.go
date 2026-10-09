//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
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
	for _, user := range []string{"qpsecond", "qpmanaged"} {
		auth := "/run/native-" + user + "-good.auth"
		file, err := os.OpenFile(auth, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		r.authPaths = append(r.authPaths, auth)
		_, err = file.WriteString("username = " + user + "\npassword = native-qemu-only-password-29\n")
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	started, err := r.owner.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("planned native daemon readiness"), err)
	}
	r.daemonPID = started.Processes.Members[0].Process.PID
	return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
}

// ProbePlannedDataAccessQEMU exercises ONLY this already-running fixed service
// role and original process inputs. Its containing coordinator retains/freshly
// verifies identity and the complete mounted roster OUTSIDE the runtime gate.
// No caller supplies a path, root, credential, command or backend. The six
// bounded clients use the existing private helper and never start a daemon.
func (r *NativeSambaRuntimeQEMU) ProbePlannedDataAccessQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || !r.plannedDataPrepared ||
		r.owner.serviceConfiguration == nil || r.daemonPID <= 1 || r.plannedDataAttempted {
		return ErrReviewRequired
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	r.plannedDataAttempted = true
	defer func() {
		if result != nil {
			r.owner.review = true // Containing coordinator stops; keep all inputs.
		}
	}()
	pid := r.daemonPID
	for _, operation := range []string{"rw-write", "rw-read", "ro-read", "ro-write", "escape", "ungranted"} {
		if err := r.verifyNativeDaemonQEMU(ctx, pid); err != nil {
			return nativeDataFailureQEMU(operation, nativeWorkerAdmissionQEMU, err)
		}
		if err := r.nativeDataClientQEMU(ctx, operation); err != nil {
			return err
		}
		if err := r.verifyNativeDaemonQEMU(ctx, pid); err != nil {
			return nativeDataFailureQEMU(operation, nativeWorkerPostAdmissionQEMU, err)
		}
	}
	// The owned daemon and its original source objects/RO-RW views have just
	// been checked. Inspect only its fixed view; these paths select no authority.
	base := "/proc/" + strconv.Itoa(pid) + "/root/shares/"
	var created unix.Stat_t
	if unix.Lstat(base+"writable/created", &created) != nil || created.Mode&unix.S_IFMT != unix.S_IFREG ||
		created.Uid != 2001 || created.Gid != 2001 || created.Size != 22 {
		return nativeDataFailureQEMU("unix-owner", nativeWorkerResultQEMU, errors.New("planned SMB write lost effective peer identity"))
	}
	fd, writeErr := unix.Open(base+"readonly/kernel-ro-proof", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if fd >= 0 {
		if err := unix.Close(fd); err != nil {
			return nativeDataFailureQEMU("kernel-ro", nativeWorkerSettlementQEMU, err)
		}
	}
	if !errors.Is(writeErr, unix.EROFS) {
		return nativeDataFailureQEMU("kernel-ro", nativeWorkerResultQEMU, errors.New("planned read-only share not kernel-enforced"))
	}
	for _, path := range []string{"/run/native-share-download-rw", "/run/native-share-download-ro"} {
		contents, err := os.ReadFile(path)
		matched := err == nil && string(contents) == "native-share-qualified"
		clear(contents)
		if !matched {
			return nativeDataFailureQEMU("transfer", nativeWorkerResultQEMU, errors.New("planned SMB transfer contents mismatch"))
		}
	}
	for _, path := range []string{"/run/native-share-download-escape", base + "readonly/forbidden", base + "readonly/kernel-ro-proof"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nativeDataFailureQEMU("denial", nativeWorkerResultQEMU, errors.New("planned SMB denial created an unintended file"))
		}
	}
	if err := r.verifyNativeDaemonQEMU(ctx, pid); err != nil {
		return nativeDataFailureQEMU("final-daemon", nativeWorkerPostAdmissionQEMU, err)
	}
	return nil
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const nativeFaultChildProof = "PHANTOWD_NATIVE_STARTUP_FAULT_CHILD_READY state_drift=true pending_retained=true groups_stopped=true capture_settled=true authority_busy=true inputs_retained=true restoration_refused=true close_no_retry=true scope=qemu-subprocess-only\n"

// No embedded Buffer/ReadFrom: os/exec's io.Copy cannot bypass the write bound.
type nativeFaultOutput struct{ buffer bytes.Buffer }

func (b *nativeFaultOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1024 {
		return 0, errors.New("fault fixture output bound")
	}
	return b.buffer.Write(p)
}

func (b *nativeFaultOutput) String() string { return b.buffer.String() }

// OS exit contains intentionally retained authority only AFTER the child proves
// verified owned-group teardown. This is fixture disposal, not product recovery.
func nativeIdentityFaultSubprocessQEMU() error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/sbin/phantowd-runtime-bundle-probe", "native-startup-fault")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.WaitDelay = 2 * time.Second
	var output nativeFaultOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.String() != nativeFaultChildProof {
		return errors.New("native startup fault subprocess proof incomplete")
	}
	return nil
}

func nativeIdentityStateFaultQEMU() error {
	commandLine, err := os.ReadFile("/proc/cmdline")
	var fs unix.Statfs_t
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		!strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("native startup fault fixture guard")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	const authority = "/run/phantowd-native-authority"
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	bootstrap, err := identityowner.Open(authority, inventory)
	if err != nil {
		return err
	}
	lookup, lookupErr := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, bootstrap)
	if err := errors.Join(lookupErr, bootstrap.Close()); err != nil {
		return err
	}
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	var callers []*os.File
	for _, path := range []string{"/run/phantowd-samba-code", "/run/phantowd-native-samba-root/etc", "/run/phantowd-native-samba-state"} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			for _, caller := range callers {
				_ = caller.Close()
			}
			return err
		}
		callers = append(callers, os.NewFile(uintptr(fd), "native-fault-caller"))
	}
	runtime, err := plan.NewNativeSambaRuntimeQEMU(ctx, callers[0], callers[1], callers[2], lookup)
	for _, caller := range callers {
		err = errors.Join(err, caller.Close())
	}
	if err != nil {
		return err
	}
	backend, err := smbexec.NewNativeBackendQEMU(ctx, runtime)
	if err != nil {
		return err
	}
	owner, err := identityowner.OpenWithSMBBackend(authority, inventory, backend)
	if err != nil {
		return err
	}
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return err
	}
	service, err := smbexec.NewNativeIdentityServiceQEMU(ctx, owner, evidence.Fingerprint, backend)
	if err != nil {
		return err
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	// Replace only this fixed guest-tmpfs alias, keeping the original directory
	// and its contents alive. The capture can retain valid original descriptors;
	// complete runtime admission must detect the changed alias BEFORE execution.
	// Mode drift instead fails inside capture construction and cannot qualify the
	// pending-capture branch. No TDB, disk or firmware bytes are altered.
	const lock = "/run/phantowd-native-samba-state/lock"
	const displaced = "/run/phantowd-native-samba-state/lock.displaced"
	if err := unix.Renameat2(unix.AT_FDCWD, lock, unix.AT_FDCWD, displaced, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := os.Mkdir(lock, 0700); err != nil {
		return err
	}
	if err := service.Observe(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("state drift did not quarantine coordinator")
	}
	// Remove only the known-empty replacement, never the displaced directory.
	if err := unix.Rmdir(lock); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, displaced, unix.AT_FDCWD, lock, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	for _, operation := range []func(context.Context) error{service.Start, service.Observe, service.Close, service.Close} {
		if err := operation(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
			return errors.New("restoration or repeated close revived coordinator")
		}
	}
	status, err := service.Status()
	if err != nil || status.State != "review-required" || !status.IdentityRetained || status.RuntimeClosed {
		return errors.New("uncertain stop released identity")
	}
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("review lost identity authority")
	}
	competing, err := identityowner.Open(authority, inventory)
	if competing != nil || !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("competing identity owner admitted during review")
	}
	observed, err := runtime.ObserveNativeStopQEMU(ctx)
	if err != nil || !observed.DaemonStopped || !observed.ClientsStopped ||
		!observed.CaptureSettled || !observed.CaptureRetained || !observed.InputsRetained || !observed.BeforeWorker {
		return errors.New("fault teardown or retained-input proof incomplete")
	}
	// Do NOT call raw runtime.Close or drop the lease to make cleanup pass.
	// The quarantined consumer/capture remain held until this test process exits.
	_, err = io.WriteString(os.Stdout, nativeFaultChildProof)
	return err
}

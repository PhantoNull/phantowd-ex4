//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

// A NEW single-use runtime on the same qualified fixture originals. The older
// complete enrollment/authentication/idle/live-revocation campaign is unchanged.
// This adds startup retention and supervised observation, not product sharing.
func nativeIdentityStartupFixtureQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup, authority string, inventory identityowner.Inventory, target string) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var callers []*os.File
	for _, path := range []string{"/run/phantowd-samba-code", "/run/phantowd-native-samba-root/etc", "/run/phantowd-native-samba-state"} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			for _, caller := range callers {
				_ = caller.Close()
			}
			return err
		}
		callers = append(callers, os.NewFile(uintptr(fd), "native-startup-fixture-caller"))
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
		return errors.Join(err, runtime.Close(context.Background()))
	}
	owner, err := identityowner.OpenWithSMBBackend(authority, inventory, backend)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, owner.Close()) }()
	journal, err := owner.SMB(target).Load(ctx)
	if err != nil || journal.Phase != smbprovision.Disabled {
		return errors.New("startup target was not previously disabled")
	}
	if err := owner.SMB(target).Enable(ctx, journal.Revision); err != nil {
		return err
	}
	// Re-enable is explicit BEFORE a service consumer exists, never a refresh
	// of an invalidated consumer or an automatic account transition.
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return err
	}
	service, err := smbexec.NewNativeIdentityServiceQEMU(ctx, owner, evidence.Fingerprint, backend)
	if service != nil {
		defer func() { result = errors.Join(result, service.Close(context.Background())) }()
	}
	if err != nil {
		return err
	}
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("identity authority released before startup")
	}
	canceled, cancelStart := context.WithCancel(ctx)
	cancelStart()
	if err := service.Start(canceled); !errors.Is(err, context.Canceled) {
		return errors.New("canceled retained startup admitted")
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	if err := service.Start(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("retained startup retried")
	}
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("identity authority released while daemon live")
	}
	if err := service.Observe(ctx); err != nil {
		return err
	}
	initial, err := service.Status()
	if err != nil || initial.State != "ready" || !initial.IdentityRetained || initial.RuntimeClosed || initial.Checks != 1 {
		return errors.New("retained startup observation incomplete")
	}
	supervisionContext, cancelSupervision := context.WithCancel(ctx)
	defer cancelSupervision()
	completed := make(chan error, 1)
	go func() { completed <- service.Supervise(supervisionContext, time.Second) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			return errors.Join(errors.New("supervision ended before a complete scan"), err)
		case <-ctx.Done():
			cancelSupervision()
			return errors.Join(ctx.Err(), <-completed)
		case <-ticker.C:
			status, err := service.Status()
			if err != nil {
				cancelSupervision()
				return errors.Join(err, <-completed)
			}
			if status.Checks <= initial.Checks {
				continue
			}
			// The status is telemetry, not authorization. Cancel only after a
			// completed scan, avoiding intentional mid-worker cancellation here.
			if err := service.Observe(ctx); !errors.Is(err, processowner.ErrBusy) {
				cancelSupervision()
				return errors.Join(errors.New("supervision did not serialize scans"), err, <-completed)
			}
			cancelSupervision()
			if err := <-completed; !errors.Is(err, context.Canceled) {
				return errors.Join(errors.New("accepted cancellation did not stop"), err)
			}
			status, err = service.Status()
			if err != nil || status.State != "stopped" || !status.IdentityRetained || status.RuntimeClosed {
				return errors.New("stop released authority before full closure")
			}
			if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
				return errors.New("stopped runtime lost identity retention")
			}
			if err := service.Close(context.Background()); err != nil {
				return err
			}
			status, err = service.Status()
			if err != nil || status.IdentityRetained || !status.RuntimeClosed || status.State != "stopped" {
				return errors.New("verified closure failed to release identity")
			}
			return owner.Close()
		}
	}
}

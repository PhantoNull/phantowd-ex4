//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
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
	defer func() { reportNativeWorkerFailureQEMU(runtime, result) }()
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
	if err != nil || journal.Phase != smbprovision.Enabled {
		return errors.New("startup target was not explicitly enrolled and enabled")
	}
	// The preceding real enrollment explicitly enables the target BEFORE this
	// NEW service consumer. Startup does not change identities automatically.
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
	if err := service.Disable(ctx, target, journal.Revision); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("prepared coordinator admitted disable before startup")
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
	if err := nativeCoordinatorDisableFixtureQEMU(service, owner, target); err != nil {
		return err
	}
	// The added live-session campaign has its own fixed45-second deadline.
	// Startup's40 seconds never governs that unrelated workload. Complete manual/
	// timed observation and accepted cancellation now have a stricter20 seconds;
	// the original worker/revocation/guest180 bounds remain unchanged.
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
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
			if err := service.Disable(ctx, target, 1); !errors.Is(err, processowner.ErrBusy) {
				cancelSupervision()
				return errors.Join(errors.New("supervision did not serialize disable"), err, <-completed)
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
			if err := service.Disable(ctx, target, 1); !errors.Is(err, runtimebundle.ErrReviewRequired) {
				return errors.New("stopped coordinator admitted disable")
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

// Actual SAME-daemon target/peer sessions, not a modeled backend or copied TDB.
// The coordinator retains and transfers its own identity consumer throughout.
func nativeCoordinatorDisableFixtureQEMU(service *smbexec.NativeIdentityServiceQEMU, owner *identityowner.Owner, target string) (result error) {
	begin := time.Now()
	stage := "admission"
	defer func() {
		if result != nil {
			result = fmt.Errorf("native coordinator disable stage=%s elapsed=%s deadline=%t canceled=%t: %w", stage, time.Since(begin), errors.Is(result, context.DeadlineExceeded), errors.Is(result, context.Canceled), result)
		}
	}()
	var journal smbprovision.Journal
	var pair smbexec.NativeSessionPairQEMU
	return runNativeCoordinatorPhasesQEMU(context.Background(), func(ctx context.Context) error {
		var err error
		journal, err = owner.SMB(target).Load(ctx)
		if err != nil || journal.Phase != smbprovision.Enabled {
			return errors.New("coordinator disable admission")
		}
		canceled, cancelDisable := context.WithCancel(ctx)
		cancelDisable()
		if err := service.Disable(canceled, target, journal.Revision); !errors.Is(err, context.Canceled) {
			return errors.New("canceled coordinator disable admitted")
		}
		stage = "session-pair"
		pair, err = service.StartNativeSessionPairQEMU(ctx)
		return err
	}, func(ctx context.Context) error {
		stage = "stale-revision"
		if err := service.Disable(ctx, target, journal.Revision-1); !errors.Is(err, smbprovision.ErrConflict) {
			return errors.New("stale coordinator disable did not refuse before intent")
		}
		unchanged, err := owner.SMB(target).Load(ctx)
		if err != nil || unchanged != journal {
			return errors.New("refused coordinator disable changed journal")
		}
		stage = "disable"
		if err := service.Disable(ctx, target, journal.Revision); err != nil {
			return err
		}
		after, err := owner.SMB(target).Load(ctx)
		if err != nil || after.Phase != smbprovision.Disabled || after.Revision != journal.Revision+2 || after.SID != journal.SID {
			return errors.New("coordinator disable successor journal mismatch")
		}
		stage = "peer-continuity"
		if err := service.VerifyNativeDisabledPairQEMU(ctx, pair); err != nil {
			return err
		}
		status, err := service.Status()
		if err != nil || status.State != "ready" || !status.IdentityRetained || status.RuntimeClosed {
			return errors.New("coordinator transition lost running authority")
		}
		if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
			return errors.New("coordinator disable released live identity")
		}
		return nil
	})
}

// Fixed fixture callbacks, not backend selection or a product timing policy.
// Preparation gets 20 seconds; original revocation/continuity/login checks keep
// their full 45 seconds. The SAME runtime, Owner and held pair cross this seam.
// Context expiry or uncertain work never proceeds/retries; all worker and
// external 180-second guest limits remain independent and unchanged.
func runNativeCoordinatorPhasesQEMU(parent context.Context, prepare, revoke func(context.Context) error) error {
	if parent == nil || prepare == nil || revoke == nil {
		return errors.New("native coordinator requires both fixture phases and parent")
	}
	budgets := [...]time.Duration{20 * time.Second, 45 * time.Second}
	for index, phase := range []func(context.Context) error{prepare, revoke} {
		if err := parent.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(parent, budgets[index])
		err := phase(ctx)
		contextErr := ctx.Err()
		cancel()
		if err != nil || contextErr != nil {
			return errors.Join(err, contextErr)
		}
	}
	return parent.Err()
}

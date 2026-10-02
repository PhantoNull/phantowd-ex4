//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fixed disposable guest fixture, not installed by any firmware package.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const fixtureRoot = "/run/phantowd-launcher-fixture/root"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_SERVICE_LAUNCHER_OWNER_FAILED:", err)
		os.Exit(1)
	}
}

func run() error {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || runtime.GOARCH != "arm" ||
		os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("requires disposable ARMv5 Versatile PB guest")
	}
	ctx := context.Background()
	fd, err := unix.Open(fixtureRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(fd), "qemu-fixed-launcher-root")
	args := []string{"--owner-probe"}
	identity := &processowner.Credentials{UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{1000}}
	var owner *processowner.IsolatedOwner
	var reportedPID int
	spec := processowner.Spec{
		Executable: "/usr/sbin/phantowd-service-launcher-fixture", Args: args, RunAs: identity,
		ReadyTimeout: 5 * time.Second, ProbeInterval: 20 * time.Millisecond, StopTimeout: time.Second,
		Ready: func(ctx context.Context) (bool, error) {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			text := string(owner.Diagnostics())
			if !strings.Contains(text, "PHANTOWD_SERVICE_SANDBOX_READY ") {
				return false, nil
			}
			var group int
			if _, err := fmt.Sscanf(text, "PHANTOWD_SERVICE_SANDBOX_READY pid=%d pgid=%d", &reportedPID, &group); err != nil || group != reportedPID {
				return false, errors.New("unexpected synthetic child evidence")
			}
			return true, nil
		},
	}
	owner, err = processowner.NewIsolated(spec, processowner.Isolation{
		LauncherExecutable: "/usr/sbin/phantowd-service-launcher", Root: root,
	})
	_ = root.Close()
	if err != nil {
		return err
	}
	defer owner.Close()
	// Caller-owned descriptor, args and credential slices must not be authority
	// after construction. A changed external spec must never change this child.
	args[0] = "replacement"
	identity.UID = 0
	identity.SupplementaryGIDs[0] = 0
	started, err := owner.Start(ctx)
	if err != nil {
		return err
	}
	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			_, _ = owner.Stop(ctx)
		}
	}()
	if started.State != processowner.StateReady || started.Generation != 1 || started.PID != reportedPID {
		return errors.New("Owner did not retain the ready isolated child's PID")
	}
	var parent, child unix.Stat_t
	if unix.Stat("/proc/self/ns/mnt", &parent) != nil ||
		unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", started.PID), &child) != nil || parent.Ino == child.Ino {
		return errors.New("Owner child did not enter its private namespace")
	}
	if !errors.Is(owner.Close(), processowner.ErrAlreadyRunning) {
		return errors.New("pinned inputs were released while the child was owned")
	}
	observed, err := owner.Observe(ctx)
	if err != nil || observed.State != processowner.StateReady || observed.PID != started.PID {
		return errors.New("Owner did not retain the isolated service")
	}
	cleanupNeeded = false
	stopped, err := owner.Stop(ctx)
	if err != nil || stopped.State != processowner.StateStopped || stopped.PID != 0 || stopped.Generation != 1 {
		return errors.New("Owner did not stop/reap the isolated group")
	}
	if err := unix.Kill(-started.PID, 0); !errors.Is(err, unix.ESRCH) {
		return errors.New("isolated process group remains")
	}
	if err := owner.Close(); err != nil {
		return err
	}
	if _, err := owner.Start(ctx); !errors.Is(err, processowner.ErrUnavailable) {
		return errors.New("closed isolated owner restarted")
	}
	fmt.Println("PHANTOWD_SERVICE_LAUNCHER_OWNER_READY pinned_inputs=true immutable_spec=true readiness=true same_pid=true private_namespace=true stop_reaped=true close_gated=true")
	// A changed pinned root must be refused before creating a process and stay
	// quarantined after restoration; no implicit fallback or automatic retry.
	fd, err = unix.Open(fixtureRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	root = os.NewFile(uintptr(fd), "qemu-fixed-quarantine-root")
	spec.Args = []string{"--owner-probe"}
	spec.RunAs = &processowner.Credentials{UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{1000}}
	owner, err = processowner.NewIsolated(spec, processowner.Isolation{
		LauncherExecutable: "/usr/sbin/phantowd-service-launcher", Root: root,
	})
	_ = root.Close()
	if err != nil {
		return err
	}
	defer owner.Close()
	if err := os.Chmod(fixtureRoot, 0700); err != nil {
		return err
	}
	denied, deniedErr := owner.Start(ctx)
	restoreErr := os.Chmod(fixtureRoot, 0755)
	if restoreErr != nil || !errors.Is(deniedErr, processowner.ErrReviewRequired) ||
		denied.State != processowner.StateReviewRequired || denied.PID != 0 || denied.Generation != 0 {
		return errors.New("pinned input loss did not quarantine before creating a child")
	}
	if _, err := owner.Start(ctx); !errors.Is(err, processowner.ErrReviewRequired) {
		return errors.New("restored input cleared quarantine")
	}
	if stopped, err := owner.Stop(ctx); !errors.Is(err, processowner.ErrReviewRequired) || stopped.PID != 0 {
		return errors.New("no-child cleanup cleared quarantine")
	}
	if err := owner.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SERVICE_LAUNCHER_INPUT_REVIEW_READY before_child=true restoration_not_retried=true")
	fd, err = unix.Open(fixtureRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	root = os.NewFile(uintptr(fd), "qemu-fixed-live-review-root")
	owner, err = processowner.NewIsolated(spec, processowner.Isolation{
		LauncherExecutable: "/usr/sbin/phantowd-service-launcher", Root: root,
	})
	_ = root.Close()
	if err != nil {
		return err
	}
	defer owner.Close()
	started, err = owner.Start(ctx)
	if err != nil {
		return err
	}
	if err := os.Chmod(fixtureRoot, 0700); err != nil {
		_, _ = owner.Stop(ctx)
		return err
	}
	observed, observeErr := owner.Observe(ctx)
	restoreErr = os.Chmod(fixtureRoot, 0755)
	if restoreErr != nil || !errors.Is(observeErr, processowner.ErrReviewRequired) ||
		observed.State != processowner.StateReviewRequired || observed.PID != 0 ||
		observed.Generation != started.Generation {
		return errors.New("live input drift did not stop the group before review")
	}
	if err := unix.Kill(-started.PID, 0); !errors.Is(err, unix.ESRCH) {
		return errors.New("input-loss quarantine retained a live group")
	}
	if _, err := owner.Start(ctx); !errors.Is(err, processowner.ErrReviewRequired) {
		return errors.New("live input restoration cleared quarantine")
	}
	if err := owner.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SERVICE_LAUNCHER_LIVE_REVIEW_READY stop_before_close=true group_reaped=true restoration_not_retried=true")
	return nil
}

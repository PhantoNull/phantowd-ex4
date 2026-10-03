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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

func ownerSupervisionFixtures(plan *runtimebundle.Plan) error {
	root, err := stageRoot(ownerFixtureBase + "/view")
	if err != nil {
		return err
	}
	defer root.Close()
	owner, err := plan.NewOwner(context.Background(), root, []processowner.MemberSpec{{Name: "static-fixture", Process: processowner.Spec{
		Executable: "/bin/fixture", Args: []string{"owner-child", ownerFixtureBase + "/control/supervised"},
		RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready: func(context.Context) (bool, error) {
			_, err := os.Stat(ownerFixtureBase + "/control/supervised.ready")
			return err == nil, nil
		},
		ReadyTimeout: 10 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: 5 * time.Second,
	}}})
	if err != nil {
		return err
	}
	defer owner.Close(context.Background())
	if err := root.Close(); err != nil {
		return err
	}
	for _, interval := range []time.Duration{0, time.Second - 1, time.Hour + 1} {
		if _, err := owner.Supervise(context.Background(), interval); !errors.Is(err, runtimebundle.ErrInvalid) {
			return errors.New("invalid supervision interval accepted")
		}
	}
	if observed, err := owner.Supervise(context.Background(), time.Second); !errors.Is(err, runtimebundle.ErrInvalid) || observed.State != processowner.StateStopped {
		return errors.New("supervision started a stopped Owner")
	}
	if observed, err := owner.Observe(context.Background()); err != nil || observed.State != processowner.StateStopped || len(observed.Processes.Members) != 1 || observed.Processes.Members[0].Process.PID != 0 {
		return errors.New("rejected supervision changed stopped lifecycle")
	}
	started, err := owner.Start(context.Background())
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("supervision control did not start"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if pid <= 1 {
		return errors.New("missing supervised child group")
	}
	rejected, rejectCancel := context.WithCancel(context.Background())
	rejectCancel()
	if _, err := owner.Supervise(rejected, time.Second); !errors.Is(err, context.Canceled) {
		return errors.New("pre-admission cancellation accepted")
	}
	if observed, err := owner.Observe(context.Background()); err != nil || observed.State != processowner.StateReady || len(observed.Processes.Members) != 1 || observed.Processes.Members[0].Process.PID != pid {
		return errors.New("rejected supervision stopped a healthy child")
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var supervisionErr error
	go func() {
		defer close(finished)
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, supervisionErr = owner.Supervise(ctx, time.Second)
			if !errors.Is(supervisionErr, processowner.ErrBusy) || time.Now().After(deadline) {
				return
			}
			// Only rejected admission is retried. It has acquired no lifecycle
			// authority and started neither a timer nor a process.
			time.Sleep(10 * time.Millisecond)
		}
	}()
	defer func() { cancel(); <-finished }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := owner.Observe(context.Background())
		if errors.Is(err, processowner.ErrBusy) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			return errors.New("supervision did not acquire exclusive lifecycle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := owner.Close(context.Background()); !errors.Is(err, processowner.ErrBusy) {
		return errors.New("concurrent close bypassed supervision")
	}
	cancel()
	<-finished
	if !errors.Is(supervisionErr, context.Canceled) || !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.New("accepted cancellation did not stop and reap")
	}
	if _, err := os.Stat(ownerFixtureBase + "/control/supervised.stopped"); err != nil {
		return errors.New("supervised cancellation was not graceful")
	}
	if err := unix.Unmount(ownerFixtureBase+"/view", 0); !errors.Is(err, unix.EBUSY) {
		return errors.New("supervised cancellation released code pins")
	}
	if err := owner.Close(context.Background()); err != nil {
		return err
	}
	for _, marker := range []string{"supervised-drift", "supervised-exit", "supervised-forced"} {
		if err := ownerSupervisedReviewFixture(plan, marker); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_CODE_OWNER_SUPERVISION_FAILED case=%s\n", marker)
			return err
		}
	}
	fmt.Println("PHANTOWD_CODE_OWNER_SUPERVISION_READY canceled=true drift=true unexpected_exit=true forced_review=true group_reaped=true pins_retained=true concurrent_refused=true scope=qemu-only")
	return nil
}

func ownerSupervisedReviewFixture(plan *runtimebundle.Plan, marker string) error {
	stopTimeout := 5 * time.Second
	switch marker {
	case "supervised-drift", "supervised-exit":
	case "supervised-forced":
		stopTimeout = 100 * time.Millisecond
	default:
		return errors.New("fixed supervision fault required")
	}
	root, err := stageRoot(ownerFixtureBase + "/view")
	if err != nil {
		return err
	}
	defer root.Close()
	owner, err := plan.NewOwner(context.Background(), root, []processowner.MemberSpec{{Name: "static-fixture", Process: processowner.Spec{
		Executable: "/bin/fixture", Args: []string{"owner-child", ownerFixtureBase + "/control/" + marker},
		RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready: func(context.Context) (bool, error) {
			_, err := os.Stat(ownerFixtureBase + "/control/" + marker + ".ready")
			return err == nil, nil
		},
		ReadyTimeout: 10 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: stopTimeout,
	}}})
	if err != nil {
		return err
	}
	defer owner.Close(context.Background())
	if err := root.Close(); err != nil {
		return err
	}
	started, err := owner.Start(context.Background())
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("supervised fault control did not start"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if pid <= 1 {
		return errors.New("missing supervised fault group")
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var observed runtimebundle.OwnerSnapshot
	var supervisionErr error
	go func() {
		defer close(finished)
		deadline := time.Now().Add(5 * time.Second)
		for {
			observed, supervisionErr = owner.Supervise(ctx, time.Second)
			if !errors.Is(supervisionErr, processowner.ErrBusy) || time.Now().After(deadline) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	defer func() { cancel(); <-finished }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := owner.Observe(context.Background())
		if errors.Is(err, processowner.ErrBusy) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			return errors.New("fault supervision did not acquire lifecycle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	switch marker {
	case "supervised-drift":
		if err := os.Chmod(ownerFixtureBase+"/source", 0700); err != nil {
			return err
		}
		defer os.Chmod(ownerFixtureBase+"/source", 0755)
	case "supervised-exit":
		// Fixed already-owned group in this disposable guest only.
		if err := unix.Kill(-pid, unix.SIGKILL); err != nil {
			return err
		}
	case "supervised-forced":
		cancel()
	}
	select {
	case <-finished:
	case <-time.After(8 * time.Second):
		return errors.New("supervisor did not finish bounded fault case")
	}
	if !errors.Is(supervisionErr, runtimebundle.ErrReviewRequired) || observed.State != processowner.StateReviewRequired || !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.New("supervised fault did not quarantine and reap")
	}
	if marker == "supervised-drift" {
		if !errors.Is(supervisionErr, runtimebundle.ErrMismatch) {
			return errors.New("code drift was not the observed cause")
		}
		if err := os.Chmod(ownerFixtureBase+"/source", 0755); err != nil {
			return err
		}
	}
	if err := unix.Unmount(ownerFixtureBase+"/view", 0); !errors.Is(err, unix.EBUSY) {
		return errors.New("review discarded code pins before explicit release")
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("restored supervised code allowed restart")
	}
	if err := owner.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("supervised code drift cleared review on release")
	}
	return nil
}

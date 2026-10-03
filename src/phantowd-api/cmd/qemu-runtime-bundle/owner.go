//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

const ownerFixtureBase = "/run/phantowd-code-owner"

// Exact QEMU/root guard is checked by run. This fixture uses a private mount
// namespace and a copied static test program in guest tmpfs, never real media.
func ownerFixture() error {
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	for _, name := range []string{ownerFixtureBase, ownerFixtureBase + "/source", ownerFixtureBase + "/view", ownerFixtureBase + "/control"} {
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
	}
	if err := os.Chown(ownerFixtureBase+"/control", 1801, 1800); err != nil {
		return err
	}
	if err := os.Mkdir(ownerFixtureBase+"/source/bin", 0755); err != nil {
		return err
	}
	// Hashing this source is a disposable fixture oracle, not release trust.
	data, err := os.ReadFile("/usr/sbin/phantowd-runtime-bundle-probe")
	if err != nil || len(data) > 16<<20 {
		return errors.New("bounded static fixture required")
	}
	if err := os.WriteFile(ownerFixtureBase+"/source/bin/fixture", data, 0555); err != nil {
		return err
	}
	if err := os.Symlink("/bin/fixture", ownerFixtureBase+"/source/bin/alias"); err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan([]runtimebundle.File{{Path: "bin/fixture", SHA256: sha256.Sum256(data), Size: int64(len(data)), Mode: 0555}}, []runtimebundle.Alias{{Path: "bin/alias", Target: "bin/fixture"}})
	if err != nil {
		return err
	}
	if err := unix.Mount(ownerFixtureBase+"/source", ownerFixtureBase+"/view", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", ownerFixtureBase+"/view", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	defer unix.Unmount(ownerFixtureBase+"/view", 0)
	root, err := stageRoot(ownerFixtureBase + "/view")
	if err != nil {
		return err
	}
	defer root.Close()
	args := []string{"owner-child", ownerFixtureBase + "/control/normal"}
	specs := []processowner.MemberSpec{{Name: "static-fixture", Process: processowner.Spec{
		Executable: "/bin/fixture", Args: args, RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready: func(context.Context) (bool, error) {
			_, err := os.Stat(ownerFixtureBase + "/control/normal.ready")
			return err == nil, nil
		},
		ReadyTimeout: 10 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: 5 * time.Second,
	}}}
	owner, err := plan.NewOwner(context.Background(), root, specs)
	if err != nil {
		return errors.Join(errors.New("retained Owner construction"), err)
	}
	defer owner.Close(context.Background())
	if err := root.Close(); err != nil {
		return err
	}
	args[0] = "wrong-fixture-mode"
	specs[0].Process.RunAs.UID = 1803
	observed, err := owner.Observe(context.Background())
	if err != nil || observed.Bundle.Files != 1 || observed.Bundle.Aliases != 1 || observed.State != processowner.StateStopped {
		return errors.Join(errors.New("independent retained inputs"), err)
	}
	started, err := owner.Start(context.Background())
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("fixed pinned launch"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if pid <= 1 {
		return errors.New("missing owned child")
	}
	started.Processes.Members[0].Process.PID = 1
	if _, err := owner.Start(context.Background()); !errors.Is(err, processowner.ErrAlreadyRunning) {
		return errors.New("duplicate start changed lifecycle authority")
	}
	if observed, err := owner.Observe(context.Background()); err != nil || observed.State != processowner.StateReady || observed.Processes.Members[0].Process.PID != pid {
		return errors.New("duplicate start stopped a healthy child")
	}
	closeCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Close(closeCtx); err != nil {
		return errors.Join(errors.New("stop/reap before retained release"), err)
	}
	if !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.New("owned process group survives release")
	}
	if _, err := os.Stat(ownerFixtureBase + "/control/normal.stopped"); err != nil {
		return errors.New("child did not finish graceful shutdown")
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, runtimebundle.ErrUnavailable) {
		return errors.New("closed Owner restarted")
	}
	fmt.Println("PHANTOWD_CODE_OWNER_READY caller_close=true fixed_spec=true pinned_exec=true duplicate_start_no_effect=true stop_reaped=true scope=qemu-only")
	if err := ownerSupervisionFixtures(plan); err != nil {
		return err
	}
	if err := ownerReviewFixtures(plan, data); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_CODE_OWNER_REVIEW_READY same_bytes_replacement=true before_child=true live_root_drift=true group_reaped=true restoration_not_retried=true scope=qemu-only")
	fmt.Println("PHANTOWD_CODE_OWNER_FORCED_REVIEW_READY forced=true pins_retained=true explicit_reap=true released_after_verification=true review_not_cleared=true scope=qemu-only")
	return nil
}

func ownerReviewFixtures(plan *runtimebundle.Plan, data []byte) error {
	newOwner := func(marker string) (*runtimebundle.Owner, error) {
		root, err := stageRoot(ownerFixtureBase + "/view")
		if err != nil {
			return nil, err
		}
		defer root.Close()
		stopTimeout := 5 * time.Second
		if marker == "forced" {
			stopTimeout = 100 * time.Millisecond
		}
		return plan.NewOwner(context.Background(), root, []processowner.MemberSpec{{Name: "static-fixture", Process: processowner.Spec{
			Executable: "/bin/fixture", Args: []string{"owner-child", ownerFixtureBase + "/control/" + marker},
			RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
			Ready: func(context.Context) (bool, error) {
				_, err := os.Stat(ownerFixtureBase + "/control/" + marker + ".ready")
				return err == nil, nil
			},
			ReadyTimeout: 10 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: stopTimeout,
		}}})
	}
	before, err := newOwner("before")
	if err != nil {
		return err
	}
	defer before.Close(context.Background())
	const original = ownerFixtureBase + "/source/bin/fixture"
	const prior = ownerFixtureBase + "/prior-fixture"
	if err := os.Rename(original, prior); err != nil {
		return err
	}
	if err := os.WriteFile(original, data, 0555); err != nil {
		return err
	}
	// A fresh point-in-time check must accept identical bytes and modes. The
	// retained Owner must still refuse the new inode before creating any child.
	root, err := stageRoot(ownerFixtureBase + "/view")
	if err != nil {
		return err
	}
	_, inspectErr := plan.Inspect(context.Background(), root)
	_ = root.Close()
	if inspectErr != nil {
		return errors.Join(errors.New("same-byte replacement control"), inspectErr)
	}
	denied, err := before.Start(context.Background())
	if !errors.Is(err, runtimebundle.ErrReviewRequired) || denied.State != processowner.StateReviewRequired || len(denied.Processes.Members) != 1 || denied.Processes.Members[0].Process.PID != 0 {
		return errors.New("replacement was not quarantined before child creation")
	}
	if err := os.Remove(original); err != nil {
		return err
	}
	if err := os.Rename(prior, original); err != nil {
		return err
	}
	if _, err := before.Start(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("restored executable cleared review")
	}
	if _, err := os.Stat(ownerFixtureBase + "/control/before.ready"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("denied child left readiness evidence")
	}
	if err := before.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("review disappeared during input release")
	}
	live, err := newOwner("live")
	if err != nil {
		return err
	}
	defer live.Close(context.Background())
	started, err := live.Start(context.Background())
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("live drift control did not start"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if err := os.Chmod(ownerFixtureBase+"/source", 0700); err != nil {
		return err
	}
	observed, err := live.Observe(context.Background())
	if !errors.Is(err, runtimebundle.ErrReviewRequired) || observed.State != processowner.StateReviewRequired || observed.Processes.Members[0].Process.PID != 0 || !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.New("live root drift did not stop and reap the group")
	}
	if _, err := os.Stat(ownerFixtureBase + "/control/live.stopped"); err != nil {
		return errors.New("drift stop was not graceful")
	}
	if err := os.Chmod(ownerFixtureBase+"/source", 0755); err != nil {
		return err
	}
	if _, err := live.Start(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("restored root cleared review")
	}
	if err := live.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("live review disappeared during input release")
	}
	forced, err := newOwner("forced")
	if err != nil {
		return err
	}
	defer forced.Close(context.Background())
	started, err = forced.Start(context.Background())
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("forced-stop control did not start"), err)
	}
	pid = started.Processes.Members[0].Process.PID
	if pid <= 1 {
		return errors.New("missing forced-stop child")
	}
	closeCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := forced.Close(closeCtx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("forced stop released inputs or cleared review")
	}
	observed, err = forced.Observe(context.Background())
	if !errors.Is(err, runtimebundle.ErrReviewRequired) || observed.State != processowner.StateReviewRequired || observed.Processes.Members[0].Process.PID != pid {
		return errors.New("uncertain ownership was discarded")
	}
	if !errors.Is(unix.Kill(-pid, 0), unix.ESRCH) {
		return errors.New("forced-stop group is still present")
	}
	// No caller root descriptor or live process remains. A normal unmount must
	// still be busy solely because the Owner retains its code/root references.
	if err := unix.Unmount(ownerFixtureBase+"/view", 0); !errors.Is(err, unix.EBUSY) {
		return errors.New("uncertain cleanup did not retain code mount pins")
	}
	if _, err := forced.Start(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("forced stop allowed a restart")
	}
	if err := forced.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("explicit reap verification cleared review")
	}
	if _, err := forced.Start(context.Background()); !errors.Is(err, runtimebundle.ErrUnavailable) {
		return errors.New("verified release left an executable Owner")
	}
	if err := unix.Unmount(ownerFixtureBase+"/view", 0); err != nil {
		return errors.Join(errors.New("verified cleanup retained mount pins"), err)
	}
	return nil
}

func ownerFixtureChild() error {
	if os.Getgid() != 1800 {
		return errors.New("fixed child guard")
	}
	switch os.Args[2] {
	case ownerFixtureBase + "/control/normal", ownerFixtureBase + "/control/before", ownerFixtureBase + "/control/live", ownerFixtureBase + "/control/forced",
		ownerFixtureBase + "/control/supervised", ownerFixtureBase + "/control/supervised-drift", ownerFixtureBase + "/control/supervised-exit", ownerFixtureBase + "/control/supervised-forced":
	default:
		return errors.New("fixed child guard")
	}
	stop := make(chan os.Signal, 1)
	if os.Args[2] == ownerFixtureBase+"/control/forced" || os.Args[2] == ownerFixtureBase+"/control/supervised-forced" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(stop, syscall.SIGTERM)
	}
	defer signal.Stop(stop)
	if err := os.WriteFile(os.Args[2]+".ready", []byte("ready"), 0600); err != nil {
		return err
	}
	select {
	case <-stop:
		return os.WriteFile(os.Args[2]+".stopped", []byte("stopped"), 0600)
	case <-time.After(15 * time.Second):
		return errors.New("unowned fixture timeout")
	}
}

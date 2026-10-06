//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Replace the unused old fixture process spec BEFORE publication. All daemon
// inputs duplicate the same admitted originals retained for credential workers.
func (r *NativeSambaRuntimeQEMU) prepareNativeDaemonQEMU(ctx context.Context) error {
	fd, err := unix.Openat(int(r.owner.configuration.contents.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(fd), "native-daemon-config-caller")
	config := [5]*os.File{root, r.owner.configuration.contents.files["passwd"], r.owner.configuration.contents.files["group"], r.owner.configuration.contents.files["nsswitch.conf"], r.owner.configuration.contents.files["samba/smb.conf"]}
	var state [7]*os.File
	for index, name := range sambaStateDirectories {
		state[index] = r.owner.sambaState.files[name]
	}
	set, err := processowner.NewNativeSambaPinnedSetQEMU(processowner.MemberSpec{Name: "native-samba", Process: processowner.Spec{
		Executable: sambaFixtureHelper, Args: []string{"native-server"}, RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready: func(ctx context.Context) (bool, error) {
			authenticated, denied, err := r.nativeClientQEMU(ctx, "qpmanaged", false)
			if denied {
				return false, ErrMismatch
			}
			return authenticated, err
		},
		ReadyTimeout: 12 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 4 * time.Second,
	}}, r.helper, config, state)
	err = errors.Join(err, root.Close())
	if err != nil {
		if set != nil {
			err = errors.Join(err, set.Close())
		}
		return err
	}
	if err := r.owner.processes.Close(); err != nil {
		return errors.Join(err, set.Close())
	}
	r.owner.processes = set
	return nil // The outer constructor performs the complete late admission.
}

// ProbeNativeDaemonQEMU is a fixed authentication-only experiment, not a product
// Start API. It keeps the private runtime gate, starts once, verifies original
// child views/owned process, then stops before returning without releasing pins.
func (r *NativeSambaRuntimeQEMU) ProbeNativeDaemonQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil {
		return ErrReviewRequired
	}
	var authPaths []string
	defer func() {
		for _, path := range authPaths {
			result = errors.Join(result, os.Remove(path))
		}
	}()
	for _, test := range []struct{ user, kind, password string }{
		{"qpmanaged", "good", "native-qemu-only-password-29"},
		{"qpsecond", "good", "native-qemu-only-password-29"},
		{"qpmanaged", "wrong", "native-qemu-wrong-password-29"},
	} {
		path := "/run/native-" + test.user + "-" + test.kind + ".auth"
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		authPaths = append(authPaths, path)
		_, err = fmt.Fprintf(file, "username = %s\npassword = %s\n", test.user, test.password)
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	defer func() {
		stopped, err := r.owner.processes.Stop(context.Background())
		r.owner.snapshot.Processes, r.owner.snapshot.State = stopped, stopped.State
		if err != nil || stopped.State != processowner.StateStopped {
			r.owner.review = true
			result = errors.Join(result, ErrReviewRequired, err)
		}
		if result != nil {
			r.owner.review = true
		}
	}()
	started, err := r.owner.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("native daemon readiness"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if err := r.verifyNativeDaemonQEMU(ctx, pid); err != nil {
		return err
	}
	for _, name := range []string{"qpmanaged", "qpsecond"} {
		authenticated, _, err := r.nativeClientQEMU(ctx, name, false)
		if err != nil || !authenticated {
			return errors.Join(errors.New("native daemon authentication refused"), err)
		}
	}
	authenticated, denied, err := r.nativeClientQEMU(ctx, "qpmanaged", true)
	if err != nil || authenticated || !denied {
		return errors.Join(errors.New("native daemon wrong-password refusal missing"), err)
	}
	return r.verifyNativeDaemonQEMU(ctx, pid)
}

func (r *NativeSambaRuntimeQEMU) nativeClientQEMU(ctx context.Context, user string, wrong bool) (authenticated, denied bool, result error) {
	if r.pending != nil || (user != "qpmanaged" && user != "qpsecond") || ctx == nil {
		return false, false, ErrInvalid
	}
	kind := "good"
	if wrong {
		kind = "wrong"
	}
	input, err := sealedNativeCredentialInputQEMU(nil)
	if err != nil {
		return false, false, err
	}
	capture, err := processowner.NewCapture(processowner.CaptureSpec{
		ExecutableLabel: sambaFixtureHelper, Args: []string{"native-client", user, kind},
		RunAs: &processowner.Credentials{UID: 0, GID: 0}, Timeout: 4 * time.Second, StopTimeout: time.Second,
	}, r.helper, input)
	err = errors.Join(err, input.Close())
	if err != nil {
		if capture != nil {
			err = errors.Join(err, capture.Close(context.Background()))
		}
		return false, false, err
	}
	r.pending = capture
	observed, runErr := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	settled, settleErr := capture.Settled(context.Background())
	closeErr := capture.Close(context.Background())
	if !settled || settleErr != nil || closeErr != nil {
		r.owner.review = true
		return false, false, ErrReviewRequired // pending remains until verified Close.
	}
	r.pending = nil
	if runErr != nil || observed.Kind != processowner.CaptureExited {
		return false, false, errors.Join(ErrReviewRequired, runErr)
	}
	output := append(observed.Stdout, observed.Stderr...)
	defer clear(output)
	if observed.ExitCode == 0 && !bytes.Contains(output, []byte("NT_STATUS_")) {
		return true, false, nil
	}
	if observed.ExitCode == 1 && bytes.Contains(output, []byte("NT_STATUS_LOGON_FAILURE")) {
		return false, true, nil
	}
	if observed.ExitCode == 1 && bytes.Contains(output, []byte("NT_STATUS_CONNECTION_REFUSED")) && bytes.Contains(output, []byte("Connection to 127.0.0.1 failed")) {
		return false, false, nil // Only the not-yet-listening readiness condition.
	}
	return false, false, ErrMismatch
}

func (r *NativeSambaRuntimeQEMU) verifyNativeDaemonQEMU(ctx context.Context, pid int) error {
	if pid <= 1 || r.owner.revalidate(ctx) != nil || r.owner.processes.CheckNativeSambaBootstrapQEMU(ctx) != nil {
		return ErrReviewRequired
	}
	group, err := unix.Getpgid(pid)
	if err != nil || group != pid {
		return ErrReviewRequired
	}
	base := "/proc/" + strconv.Itoa(pid)
	status, err := os.ReadFile(base + "/status")
	if err != nil || len(status) > 64<<10 {
		return ErrMismatch
	}
	for _, field := range []string{"CapEff:\t00000000000000db", "CapPrm:\t00000000000000db", "CapBnd:\t00000000000000db", "CapInh:\t0000000000000000", "CapAmb:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !bytes.Contains(status, []byte(field+"\n")) {
			return ErrMismatch
		}
	}
	root, err := os.Readlink(base + "/root")
	parentNS, parentErr := os.Readlink("/proc/self/ns/mnt")
	childNS, childErr := os.Readlink(base + "/ns/mnt")
	if err != nil || root != "/run/phantowd-native-samba-root" || parentErr != nil || childErr != nil || parentNS == childNS {
		return ErrMismatch
	}
	for _, path := range []string{"proc", "dev", "run"} {
		if _, err := os.Lstat(base + "/root/" + path); !errors.Is(err, os.ErrNotExist) {
			return ErrMismatch
		}
	}
	var rootFS, ipcFS unix.Statfs_t
	if unix.Statfs(base+"/root", &rootFS) != nil || unix.Statfs(base+"/root/tmp", &ipcFS) != nil ||
		rootFS.Flags&unix.ST_RDONLY == 0 || ipcFS.Flags&unix.ST_RDONLY == 0 || rootFS.Fsid != ipcFS.Fsid {
		return ErrMismatch
	}
	actual, err := os.Stat(base + "/exe")
	expected, expectedErr := r.owner.files["usr/sbin/smbd"].Stat()
	if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
		return errors.New("native daemon code object changed")
	}
	for name, pin := range r.owner.files {
		actual, err := os.Stat(base + "/root/" + name)
		expected, expectedErr := pin.Stat()
		if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
			return errors.New("native daemon code view changed")
		}
	}
	for name, pin := range r.owner.configuration.contents.files {
		actual, err := os.Stat(base + "/root/etc/" + name)
		expected, expectedErr := pin.Stat()
		if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
			return errors.New("native daemon original configuration mismatch")
		}
	}
	return r.owner.verifyLiveSambaStateQEMU(pid)
}

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

// StartNativeDaemonQEMU is a single-use fixed experiment. Each operation keeps
// the runtime gate; the owned daemon survives between operations so the fixed
// Owner-bound backend can run credential/status workers without recursive gates.
// This is not product startup and accepts no caller-selected process or profile.
func (r *NativeSambaRuntimeQEMU) StartNativeDaemonQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonAttempted {
		return ErrReviewRequired
	}
	r.daemonAttempted = true
	defer func() {
		if result != nil {
			r.owner.review = true
			result = errors.Join(result, r.stopNativeDaemonQEMU())
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
		r.authPaths = append(r.authPaths, path)
		_, err = fmt.Fprintf(file, "username = %s\npassword = %s\n", test.user, test.password)
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	started, err := r.owner.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("native daemon readiness"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	r.daemonPID = pid
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

// VerifyNativeIdleDisableQEMU tests only the fixed qpmanaged/qpsecond pair.
// It does not claim that an established session was revoked: this first tracer
// proves workers against the live daemon and new-login refusal independently.
func (r *NativeSambaRuntimeQEMU) VerifyNativeIdleDisableQEMU(ctx context.Context) (result error) {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonPID == 0 {
		return ErrReviewRequired
	}
	defer func() {
		if result != nil {
			r.owner.review = true
		}
	}()
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	authenticated, denied, err := r.nativeClientQEMU(ctx, "qpmanaged", false)
	if err != nil || authenticated || !denied {
		return errors.Join(ErrMismatch, err)
	}
	authenticated, _, err = r.nativeClientQEMU(ctx, "qpsecond", false)
	if err != nil || !authenticated {
		return errors.Join(ErrMismatch, err)
	}
	return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
}

func (r *NativeSambaRuntimeQEMU) StopNativeDaemonQEMU(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed {
		return nil
	}
	return r.stopNativeDaemonQEMU()
}

// Guard startup construction without entering the identity Owner or accepting
// caller-selected runtime/process inputs. Credential workers may already have
// completed, but the authentication daemon/held clients must never have started.
func (r *NativeSambaRuntimeQEMU) CheckNativeStartupQEMU(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonAttempted || r.clientsAttempted {
		return ErrReviewRequired
	}
	return r.owner.revalidate(ctx)
}

// An unsettled credential capture must not be hidden by successful daemon stop.
// Preserve it for explicit recovery; stop the daemon/client groups, but do not
// claim whole-service settlement or retry an uncertain worker close.
func (r *NativeSambaRuntimeQEMU) StopNativeServiceQEMU(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed {
		return ErrReviewRequired
	}
	err := r.stopNativeDaemonQEMU()
	if r.pending != nil {
		r.owner.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	return err
}

func (r *NativeSambaRuntimeQEMU) stopNativeDaemonQEMU() error {
	var clientErr error
	if r.clients != nil {
		clients, err := r.clients.Stop(context.Background())
		clientErr = err
		if clients.State != processowner.StateStopped {
			clientErr = errors.Join(clientErr, ErrReviewRequired)
		}
	}
	stopped, err := r.owner.processes.Stop(context.Background())
	r.owner.snapshot.Processes, r.owner.snapshot.State = stopped, stopped.State
	if err != nil || clientErr != nil || stopped.State != processowner.StateStopped {
		r.owner.review = true
		return errors.Join(ErrReviewRequired, clientErr, err)
	}
	r.daemonPID = 0
	return r.removeNativeAuthQEMU()
}

func (r *NativeSambaRuntimeQEMU) removeNativeAuthQEMU() error {
	var result error
	var remaining []string
	for _, path := range r.authPaths {
		if err := os.Remove(path); err != nil {
			result = errors.Join(result, err)
			remaining = append(remaining, path)
		}
	}
	r.authPaths = remaining
	return result
}

// ProbeNativeDaemonQEMU retains the original bounded authentication experiment.
func (r *NativeSambaRuntimeQEMU) ProbeNativeDaemonQEMU(ctx context.Context) error {
	if err := r.StartNativeDaemonQEMU(ctx); err != nil {
		return err
	}
	return r.StopNativeDaemonQEMU(context.Background())
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
	if observed.ExitCode == 1 && (bytes.Contains(output, []byte("NT_STATUS_LOGON_FAILURE")) ||
		(!wrong && bytes.Contains(output, []byte("NT_STATUS_ACCOUNT_DISABLED")))) {
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
	observed, err := r.owner.processes.Observe(ctx)
	if err != nil || observed.State != processowner.StateReady || len(observed.Members) != 1 || observed.Members[0].Process.PID != pid {
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

// Exactly one complete admission on each side of every worker. Live daemon
// verification already includes the complete code/config/state revalidation;
// repeating it would consume the existing bounded status deadline before exec.
func (r *NativeSambaRuntimeQEMU) revalidateNativeRuntimeQEMU(ctx context.Context) error {
	if r.daemonPID != 0 {
		return r.verifyNativeDaemonQEMU(ctx, r.daemonPID)
	}
	return r.owner.revalidate(ctx)
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed guest-only inputs; negotiation only, no authentication/tree/file request.
func (p *Plan) ProbeServerObserverRuntimeQEMU(ctx context.Context, code *os.File) (result error) {
	if ctx == nil || p == nil || code == nil || serverObserverCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	open := func(name string) (*os.File, error) {
		fd, err := unix.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), "fixed-observer-runtime-fixture-root"), nil
	}
	configuration, err := open("/run/phantowd-native-samba-root/etc")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, configuration.Close()) }()
	state, err := open("/run/phantowd-native-samba-state")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	var shares [2]*os.File
	for i, name := range []string{"/run/observer-readonly", "/run/observer-writable"} {
		shares[i], err = open(name)
		if err != nil {
			return err
		}
		defer func(pin *os.File) { result = errors.Join(result, pin.Close()) }(shares[i])
	}
	// Initialize runtime pipe polling before comparing steady-state FD counts.
	a, b, err := os.Pipe()
	if err != nil {
		return err
	}
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	r, err := newServerObserverRuntimeQEMU(ctx, p, code, configuration, state, shares)
	if err != nil {
		return err
	}
	defer func() {
		if r.closed {
			return
		}
		stopped, stopErr := r.Stop(context.Background())
		closeErr := r.Close()
		if closeErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
			result = errors.Join(result, errors.New("observer runtime disposal not verified"), stopErr, closeErr)
		}
	}()
	started, err := r.Start(ctx)
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("retained observer runtime negotiation"), err)
	}
	if _, err := r.Observe(ctx); err != nil {
		return errors.Join(errors.New("healthy same-runtime observation"), err)
	}
	if err := r.Close(); !errors.Is(err, processowner.ErrAlreadyRunning) {
		return errors.New("live observer runtime released originals")
	}
	// Sender checks alone cannot detect an original receiver option change.
	if err := unix.SetsockoptInt(int(r.channel.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 0); err != nil {
		return err
	}
	restoreReceiver := true
	defer func() {
		if restoreReceiver {
			result = errors.Join(result, unix.SetsockoptInt(int(r.channel.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 1))
		}
	}()
	observed, err := r.Observe(ctx)
	if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired ||
		len(observed.Members) != 1 || observed.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("receiver drift did not settle original daemon and retain review"), err)
	}
	for _, pin := range r.code.code.files {
		if _, err := pin.Stat(); err != nil {
			return errors.Join(errors.New("fault released original code"), err)
		}
	}
	for _, pin := range []*os.File{r.channel.receiver, r.channel.sender, r.proc, r.code.anchor} {
		if _, err := pin.Stat(); err != nil {
			return errors.Join(errors.New("fault released original channel/process reference"), err)
		}
	}
	if err := unix.SetsockoptInt(int(r.channel.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return err
	}
	restoreReceiver = false
	if _, err := r.Observe(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("receiver restoration cleared reviewed observation")
	}
	if _, err := r.Start(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("receiver restoration restarted the daemon")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	stopped, err := r.Stop(canceled)
	if !errors.Is(err, ErrReviewRequired) || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("reviewed canceled cleanup lost verified settlement"), err)
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := p.serverObserverLiveCodeFaultQEMU(ctx, code, configuration, state, shares); err != nil {
		return err
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.Join(errors.New("observer runtime descriptor leak"), err)
	}
	fmt.Println("PHANTOWD_SERVER_OBSERVER_RUNTIME_PROOF actual_smbd=true complete_code_retained=true original_channel_pair=true receiver_drift_stopped=true live_code_cover_stopped=true originals_retained=true restoration_refused=true stop_before_release=true scope=qemu-only")
	return nil
}

func (p *Plan) serverObserverLiveCodeFaultQEMU(ctx context.Context, code, configuration, state *os.File, shares [2]*os.File) (result error) {
	r, err := newServerObserverRuntimeQEMU(ctx, p, code, configuration, state, shares)
	if err != nil {
		return err
	}
	defer func() {
		if r.closed {
			return
		}
		stopped, stopErr := r.Stop(context.Background())
		closeErr := r.Close()
		if closeErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
			result = errors.Join(result, errors.New("live-code fixture disposal not verified"), stopErr, closeErr)
		}
	}()
	started, err := r.Start(ctx)
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("live-code fixture negotiation"), err)
	}
	if _, err := r.Observe(ctx); err != nil {
		return err
	}
	// Cover only the explicitly prepared guest RAM code path. The child's
	// detached original code and our complete original census remain accessible.
	if err := unix.Mount("tmpfs", "/"+serverObserverCodePathQEMU, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "size=64k,mode=0700"); err != nil {
		return err
	}
	covered := true
	defer func() {
		if covered {
			result = errors.Join(result, unix.Unmount("/"+serverObserverCodePathQEMU, 0))
		}
	}()
	if err := r.code.code.revalidate(ctx); err != nil {
		return errors.Join(errors.New("hidden original census control"), err)
	}
	observed, err := r.Observe(ctx)
	if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired || len(observed.Members) != 1 || observed.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("live code cover did not settle and review the original daemon"), err)
	}
	for _, pins := range []map[string]*os.File{r.code.code.files, r.configuration.contents.files, r.state.files} {
		for _, pin := range pins {
			if _, err := pin.Stat(); err != nil {
				return errors.Join(errors.New("code fault released original input"), err)
			}
		}
	}
	for _, pin := range []*os.File{r.proc, r.code.code.root, r.code.anchor, r.configuration.contents.root, r.state.root, r.shares[0], r.shares[1], r.channel.receiver, r.channel.sender} {
		if _, err := pin.Stat(); err != nil {
			return errors.Join(errors.New("code fault lost original authority reference"), err)
		}
	}
	if err := unix.Unmount("/"+serverObserverCodePathQEMU, 0); err != nil {
		return err
	}
	covered = false
	if err := r.code.code.revalidate(ctx); err != nil {
		return errors.Join(errors.New("restored original code census"), err)
	}
	if _, err := r.Observe(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("code restoration cleared review")
	}
	if _, err := r.Start(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("code restoration restarted daemon")
	}
	if err := r.Close(); err != nil {
		return err
	}
	return nil
}

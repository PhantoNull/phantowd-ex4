//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed disposable composition prerequisite: bootstrap/state initialization and
// NEGOTIATE only. Not authentication success, file OPEN, samples or authority.
func (p *Plan) ProbeServerCaptureRuntimeQEMU(ctx context.Context, code *os.File) (result error) {
	if ctx == nil || p == nil || code == nil || serverObserverCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	var roots [4]*os.File
	for i, name := range []string{"/run/phantowd-native-samba-root/etc", "/run/phantowd-native-samba-state", "/run/observer-readonly", "/run/observer-writable"} {
		fd, err := unix.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		roots[i] = os.NewFile(uintptr(fd), "original-fixed-capture-input-root")
		defer func(f *os.File) { result = errors.Join(result, f.Close()) }(roots[i])
	}
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
	r, err := newServerCaptureRuntimeQEMU(ctx, p, code, roots[0], roots[1], [2]*os.File{roots[2], roots[3]})
	if err != nil {
		return err
	}
	defer func() {
		if !r.closed {
			stopped, stopErr := r.Stop(context.Background())
			closeErr := r.Close()
			if closeErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
				result = errors.Join(result, errors.New("capture runtime disposal unverified"), stopErr, closeErr)
			}
		}
	}()
	started, err := r.Start(ctx)
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("capture runtime startup"), err)
	}
	if _, err := r.Observe(ctx); err != nil {
		return err
	}
	if err := r.Close(); !errors.Is(err, processowner.ErrAlreadyRunning) {
		return errors.New("capture released original inputs while live")
	}
	module := r.code.code.files[serverCaptureModuleObjectQEMU]
	if module == nil {
		return errors.New("module not retained")
	}
	if _, err := module.Stat(); err != nil {
		return err
	}
	stopped, err := r.Stop(context.Background())
	if err != nil || stopped.State != processowner.StateStopped || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("capture daemon group did not settle"), err)
	}
	if _, err := module.Stat(); err != nil {
		return errors.New("stop released original module prematurely")
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := p.serverCaptureExistingStateRefusalQEMU(ctx, code, roots); err != nil {
		return err
	}
	after, err := retainedFixtureFDCount()
	if err != nil || before != after {
		return errors.Join(errors.New("capture runtime descriptor leak"), err)
	}
	fmt.Println("PHANTOWD_CAPTURE_RUNTIME_PROOF actual_smbd=true module_retained=true original_channel_pair=true stop_before_release=true existing_passdb_refused=true unchanged_passdb=true fd_equal=true authentication=false file_open=false samples=false authority=false scope=qemu-only")
	return nil
}

func (p *Plan) serverCaptureExistingStateRefusalQEMU(ctx context.Context, code *os.File, roots [4]*os.File) (result error) {
	fd, err := openBeneath(int(roots[1].Fd()), "private/passdb.tdb", unix.O_RDONLY)
	if err != nil {
		return err
	}
	passdb := os.NewFile(uintptr(fd), "original-synthetic-passdb")
	defer func() { result = errors.Join(result, passdb.Close()) }()
	var before unix.Stat_t
	// The actual one-account ARM TDB allocates421888 bytes. This new fixture's
	// bounded streaming hash is not a product passdb size/admission policy.
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 || before.Nlink != 1 || before.Size <= 0 || before.Size > 1<<20 {
		return ErrMismatch
	}
	hash := func() ([32]byte, error) {
		h := sha256.New()
		count, err := io.Copy(h, io.NewSectionReader(passdb, 0, before.Size))
		if err == nil && count != before.Size {
			err = io.ErrUnexpectedEOF
		}
		var result [32]byte
		copy(result[:], h.Sum(nil))
		return result, err
	}
	digest, err := hash()
	if err != nil {
		return err
	}
	r, err := newServerCaptureRuntimeQEMU(ctx, p, code, roots[0], roots[1], [2]*os.File{roots[2], roots[3]})
	if err != nil {
		return err
	}
	defer func() {
		if !r.closed {
			stopped, stopErr := r.Stop(context.Background())
			closeErr := r.Close()
			if closeErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
				result = errors.Join(result, errors.New("existing-state disposal unverified"), stopErr, closeErr)
			}
		}
	}()
	observed, err := r.Start(ctx)
	if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired || len(observed.Members) != 1 || observed.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("existing passdb startup was not refused and settled"), err)
	}
	for _, pin := range []*os.File{r.code.code.files[serverCaptureModuleObjectQEMU], r.code.code.files[serverObserverBootstrapObjectQEMU], r.channel.sender, r.channel.receiver, r.state.root} {
		if pin == nil {
			return ErrMismatch
		}
		if _, err := pin.Stat(); err != nil {
			return errors.Join(errors.New("review released original inputs"), err)
		}
	}
	if _, err := r.Start(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("reviewed bootstrap retried")
	}
	current, err := hash()
	var after unix.Stat_t
	if err != nil || unix.Fstat(fd, &after) != nil || current != digest || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid ||
		before.Nlink != after.Nlink || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.Join(errors.New("refused bootstrap changed original passdb"), err)
	}
	return r.Close()
}

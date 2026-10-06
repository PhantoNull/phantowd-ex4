//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed first worker tracer: no arbitrary tool/action/account, password, device
// or returned raw listing. The synthetic qpwriter identity is not an Owner-
// derived native account; this qualifies state-bound execution, not enrollment.
func (o *Owner) probeSambaStateObserverQEMU(ctx context.Context) (result error) {
	if err := o.revalidate(ctx); err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	fd, err := unix.Open(sambaFixtureHelper, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	helper := os.NewFile(uintptr(fd), "fixed-state-observer-bootstrap")
	defer func() {
		if helper != nil {
			result = errors.Join(result, helper.Close())
		}
	}()
	fd, err = unix.MemfdCreate("empty-state-observation-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return err
	}
	empty := os.NewFile(uintptr(fd), "empty-state-observation-input")
	defer func() {
		if empty != nil {
			result = errors.Join(result, empty.Close())
		}
	}()
	if unix.Fchmod(fd, 0600) != nil {
		return ErrUnavailable
	}
	if _, err := unix.FcntlInt(empty.Fd(), unix.F_ADD_SEALS,
		unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return err
	}
	fd, err = unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	input := os.NewFile(uintptr(fd), "readonly-empty-state-observation-input")
	defer func() {
		if input != nil {
			result = errors.Join(result, input.Close())
		}
	}()
	var inputs [7]*os.File
	closeInputs := func() (err error) {
		for index, file := range inputs {
			if file != nil {
				err = errors.Join(err, file.Close())
				inputs[index] = nil
			}
		}
		return err
	}
	defer func() { result = errors.Join(result, closeInputs()) }()
	for index, name := range sambaStateDirectories {
		fd, err := unix.FcntlInt(o.sambaState.files[name].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		inputs[index] = os.NewFile(uintptr(fd), "temporary-state-observer-caller")
	}
	preRefusal, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	invalid := inputs
	invalid[6] = inputs[0]
	rejected, admissionErr := processowner.NewSambaStateObservationCaptureQEMU(helper, input, invalid)
	if rejected != nil {
		return errors.Join(errors.New("duplicate observer state input admitted"), rejected.Close(context.Background()))
	}
	postRefusal, err := retainedFixtureFDCount()
	if !errors.Is(admissionErr, processowner.ErrInvalid) || err != nil || postRefusal != preRefusal {
		return errors.New("observer refusal leaked partial pins")
	}
	capture, err := processowner.NewSambaStateObservationCaptureQEMU(helper, input, inputs)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, capture.Close(context.Background())) }()
	// Every temporary source reference closes before launch. The daemon's
	// containing authority retains its own independent, still-valid originals.
	err = errors.Join(closeInputs(), helper.Close(), input.Close(), empty.Close())
	helper, input, empty = nil, nil, nil
	if err != nil {
		return err
	}
	observed, err := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	if err != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 {
		return errors.Join(errors.New("state-bound passdb worker failed"), err)
	}
	const marker = "PHANTOWD_SAMBA_STATE_OBSERVER_HANDOFF_READY inputs=7 source_path_masked=true same_objects=true closed_before_exec=true scope=qemu-only\n"
	if strings.Count(string(observed.Stderr), marker) != 1 {
		return errors.New("state-bound passdb bootstrap evidence absent")
	}
	rows := strings.Split(strings.TrimSuffix(string(observed.Stdout), "\n"), "\n")
	if len(rows) != 1 || len(rows[0]) > 256 || !strings.HasPrefix(rows[0], "qpwriter:1801:") ||
		strings.ContainsAny(rows[0], "\x00\r") {
		return errors.New("state-bound passdb observation missing or ambiguous")
	}
	repeated, err := capture.Capture(ctx)
	if !errors.Is(err, processowner.ErrCaptureConsumed) || repeated.Kind != processowner.CaptureUnknown ||
		repeated.ExitCode != 0 || repeated.Stdout != nil || repeated.Stderr != nil {
		return errors.New("state observation repeated or exposed partial output")
	}
	if settled, err := capture.Settled(ctx); err != nil || !settled {
		return errors.New("state observer group not verified absent")
	}
	if err := capture.Close(context.Background()); err != nil {
		return err
	}
	closed, err := capture.Capture(ctx)
	if !errors.Is(err, processowner.ErrUnavailable) || closed.Kind != processowner.CaptureUnknown ||
		closed.ExitCode != 0 || closed.Stdout != nil || closed.Stderr != nil {
		return errors.New("closed state observer reused")
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.New("state observer leaked retained inputs")
	}
	return o.revalidate(ctx)
}

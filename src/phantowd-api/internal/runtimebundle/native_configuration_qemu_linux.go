//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// ProbeNativeLookupConfigurationQEMU uses only the fixed independent native
// lookup root, after the old Samba Owners close. It qualifies original config
// retention during actual libc execution, not a SAME-state credential backend
// or daemon. No arbitrary path, tool, account, secret or callback is accepted.
func ProbeNativeLookupConfigurationQEMU(ctx context.Context, lookup fileserviceplan.SambaEnrollmentLookup) (result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || ctx == nil ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	expected, err := nativeLookupConfiguration(lookup)
	if err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	const config = "/run/phantowd-native-lookup/etc"
	// The writable original is retained ONLY for a controlled fixture metadata
	// fault. No capture receives it. All other native document tests have ended.
	writer, err := os.Open(config + "/passwd")
	if err != nil {
		return err
	}
	defer func() {
		if writer != nil {
			result = errors.Join(result, writer.Close())
		}
	}()
	if err := unix.Mount(config, config, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", config, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	fd, err := unix.Open(config, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	caller := os.NewFile(uintptr(fd), "native-configuration-caller")
	retained, err := expected.retain(ctx, caller)
	err = errors.Join(err, caller.Close())
	if err != nil {
		if retained != nil {
			err = errors.Join(err, retained.release())
		}
		return err
	}
	// Release is explicitly ordered after verified capture teardown below. An
	// uncertain group holds the configuration pins, rather than pretending stop.
	capture, err := nativeConfigurationCaptureQEMU(retained, true)
	if err != nil {
		if capture != nil {
			err = errors.Join(err, capture.Close(context.Background()))
		}
		return errors.Join(err, retained.release())
	}
	if err := retained.revalidate(ctx); err != nil {
		return errors.Join(err, capture.Close(context.Background()), retained.release())
	}
	observed, runErr := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	const positive = "PHANTOWD_NATIVE_LIBC_LOOKUP_READY accounts=2 private_groups=true foreign_omitted=true readonly_root=true caps_zero=true no_state=true scope=qemu-only\n"
	const handoff = "PHANTOWD_NATIVE_CONFIG_HANDOFF_READY inputs=4 source_path_masked=true same_objects=true closed_before_exec=true scope=qemu-only\n"
	settled, settleErr := capture.Settled(ctx)
	closeErr := capture.Close(context.Background())
	if !settled || settleErr != nil || closeErr != nil {
		return errors.Join(errors.New("native configuration worker teardown uncertain"), runErr, settleErr, closeErr)
	}
	releaseAllowed := true
	defer func() {
		if releaseAllowed {
			result = errors.Join(result, retained.release())
		}
	}()
	if runErr != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 ||
		string(observed.Stdout) != positive || string(observed.Stderr) != handoff {
		return errors.Join(errors.New("retained native configuration libc failed"), runErr)
	}
	if err := retained.revalidate(ctx); err != nil {
		return err
	}
	// Admit a fresh single-use worker before the fault, but never execute it.
	// Its own late-input fence must refuse before launch and preserve review
	// after restoration; this is capture review, not product service recovery.
	late, err := nativeConfigurationCaptureQEMU(retained, false)
	if err != nil {
		return err
	}
	releaseAllowed = false
	if err := writer.Chmod(0600); err != nil {
		closeErr := late.Close(context.Background())
		releaseAllowed = closeErr == nil // No launch, but verified close still required.
		return errors.Join(err, closeErr)
	}
	drift := retained.revalidate(ctx)
	refused, refusalErr := late.Capture(ctx)
	restoreErr := writer.Chmod(0644)
	restored, restoredErr := late.Capture(ctx)
	lateSettled, lateSettleErr := late.Settled(ctx)
	lateCloseErr := late.Close(context.Background())
	if !lateSettled || lateSettleErr != nil || lateCloseErr != nil {
		return errors.Join(errors.New("late native capture teardown uncertain"), lateSettleErr, lateCloseErr)
	}
	releaseAllowed = true
	if restoreErr != nil || drift == nil || retained.revalidate(ctx) == nil ||
		!errors.Is(refusalErr, processowner.ErrReviewRequired) || !errors.Is(restoredErr, processowner.ErrReviewRequired) ||
		refused.Kind != processowner.CaptureUnknown || restored.Kind != processowner.CaptureUnknown ||
		len(refused.Stdout) != 0 || len(refused.Stderr) != 0 || len(restored.Stdout) != 0 || len(restored.Stderr) != 0 {
		return errors.Join(errors.New("native configuration drift or restored capture review accepted"), restoreErr)
	}
	if err := retained.release(); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	// writer's deferred close must not double-close a descriptor reused later.
	writer = nil
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.New("native configuration retention leaked descriptors")
	}
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_CONFIG_READY owner_derived=true exact_census=true readonly_noexec=true caller_close=true libc=true drift_refused=true restoration_mismatch=true stopped_reaped=true released=true no_fd_leak=true scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_HANDOFF_READY inputs=4 refusals=7 source_path_masked=true same_objects=true caller_close=true readonly_noexec=true closed_before_exec=true late_drift_refused=true review_sticky=true partial_cleanup=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
	return nil
}

// Every temporary helper/input/config caller closes BEFORE returning the
// capture. Authority pins stay with retained, never with a pathname getter.
func nativeConfigurationCaptureQEMU(retained *retainedConfiguration, refusals bool) (capture *processowner.CaptureOwner, result error) {
	var callers []*os.File
	defer func() {
		for _, caller := range callers {
			result = errors.Join(result, caller.Close())
		}
		if result != nil && capture != nil {
			result = errors.Join(result, capture.Close(context.Background()))
			capture = nil
		}
	}()
	helper, err := os.Open(sambaFixtureHelper)
	if err != nil {
		return nil, err
	}
	callers = append(callers, helper)
	input, err := os.Open("/run/phantowd-native-authority/empty-input")
	if err != nil {
		return nil, err
	}
	callers = append(callers, input)
	// Open only "." relative to the retained original root, not the host path.
	fd, err := unix.Openat(int(retained.contents.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var inputs [4]*os.File
	inputs[0] = os.NewFile(uintptr(fd), "native-config-root-caller")
	callers = append(callers, inputs[0])
	for index, name := range []string{"passwd", "group", "nsswitch.conf"} {
		fd, err := unix.FcntlInt(retained.contents.files[name].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		inputs[index+1] = os.NewFile(uintptr(fd), "native-config-file-caller")
		callers = append(callers, inputs[index+1])
	}
	if refusals {
		if err := nativeConfigurationAdmissionRefusalsQEMU(helper, input, inputs); err != nil {
			return nil, err
		}
	}
	return processowner.NewNativeLookupCaptureQEMU(helper, input, inputs)
}

func nativeConfigurationAdmissionRefusalsQEMU(helper, input *os.File, inputs [4]*os.File) error {
	fd, err := unix.FcntlInt(inputs[3].Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	closed := os.NewFile(uintptr(fd), "closed-native-config-input")
	if err := closed.Close(); err != nil {
		return err
	}
	trials := make([][4]*os.File, 0, 6)
	for _, last := range []*os.File{nil, closed, inputs[1], inputs[0]} {
		trial := inputs
		trial[3] = last
		trials = append(trials, trial)
	}
	regularRoot := inputs
	regularRoot[0] = inputs[1]
	trials = append(trials, regularRoot)
	swapped := inputs
	swapped[1], swapped[2] = inputs[2], inputs[1]
	trials = append(trials, swapped)
	for index := 0; index < 7; index++ {
		trial, stdin := inputs, input
		if index < len(trials) {
			trial = trials[index]
		} else {
			stdin = inputs[3] // Valid regular read-only input, but non-empty.
		}
		before, err := retainedFixtureFDCount()
		if err != nil {
			return err
		}
		capture, err := processowner.NewNativeLookupCaptureQEMU(helper, stdin, trial)
		if capture != nil {
			_ = capture.Close(context.Background())
			return errors.New("invalid native configuration worker admitted")
		}
		if !errors.Is(err, processowner.ErrInvalid) {
			return errors.Join(errors.New("wrong native configuration admission refusal"), err)
		}
		for _, caller := range append([]*os.File{helper, input}, inputs[:]...) {
			if _, err := caller.Stat(); err != nil {
				return errors.New("refusal consumed its native configuration caller")
			}
		}
		after, err := retainedFixtureFDCount()
		if err != nil || before != after {
			return errors.New("partial native configuration admission leaked descriptors")
		}
	}
	return nil
}

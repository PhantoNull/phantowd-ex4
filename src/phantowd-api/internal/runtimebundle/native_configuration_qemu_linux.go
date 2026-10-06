//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

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
	helper, err := os.Open(sambaFixtureHelper)
	if err != nil {
		return errors.Join(err, retained.release())
	}
	input, err := os.Open("/run/phantowd-native-authority/empty-input")
	if err != nil {
		return errors.Join(err, helper.Close(), retained.release())
	}
	capture, err := processowner.NewCapture(processowner.CaptureSpec{
		ExecutableLabel: sambaFixtureHelper, Args: []string{"native-lookup"},
		RunAs: &processowner.Credentials{UID: 0, GID: 0}, Timeout: 10 * time.Second, StopTimeout: time.Second,
	}, helper, input)
	err = errors.Join(err, helper.Close(), input.Close())
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
	settled, settleErr := capture.Settled(ctx)
	closeErr := capture.Close(context.Background())
	if !settled || settleErr != nil || closeErr != nil {
		return errors.Join(errors.New("native configuration worker teardown uncertain"), runErr, settleErr, closeErr)
	}
	defer func() { result = errors.Join(result, retained.release()) }()
	if runErr != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 ||
		string(observed.Stdout) != positive || len(observed.Stderr) != 0 {
		return errors.Join(errors.New("retained native configuration libc failed"), runErr)
	}
	if err := retained.revalidate(ctx); err != nil {
		return err
	}
	if err := writer.Chmod(0600); err != nil {
		return err
	}
	drift := retained.revalidate(ctx)
	restoreErr := writer.Chmod(0644)
	if restoreErr != nil || drift == nil || retained.revalidate(ctx) == nil {
		return errors.Join(errors.New("native configuration drift or changed generation accepted"), restoreErr)
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
	return nil
}

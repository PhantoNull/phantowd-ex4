//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type captureInputFaultKindQEMU string

func parseCaptureInputFaultMarkerQEMU(line []byte) (captureInputFaultKindQEMU, error) {
	if len(line) > 4096 {
		return "", ErrInvalid
	}
	var kind captureInputFaultKindQEMU
	workerExit := false
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_worker_exit_fixture=1" {
			workerExit = true
		}
		const prefix = "phantowd_capture_input_fault_fixture="
		if !strings.HasPrefix(field, prefix) {
			continue
		}
		value := captureInputFaultKindQEMU(strings.TrimPrefix(field, prefix))
		if kind != "" || (value != "module" && value != "configuration" && value != "channel") {
			return "", ErrInvalid
		}
		kind = value
	}
	if workerExit && kind != "" {
		return "", ErrInvalid
	}
	return kind, nil
}

// Fixed fixture mutation, never a product configuration/launcher selector.
// Successful containment must precede restoring the prepared guest RAM input.
type captureInputCoverQEMU struct {
	kind              captureInputFaultKindQEMU
	target, directory string
	receiver          *os.File
	restoreTried      bool
	restoreErr        error
}

func newCaptureInputCoverQEMU(ctx context.Context, r *serverObserverRuntimeQEMU, kind captureInputFaultKindQEMU) (*captureInputCoverQEMU, error) {
	if ctx == nil || r == nil || serverObserverCodeGuardQEMU() != nil {
		return nil, ErrInvalid
	}
	line, err := os.ReadFile("/proc/cmdline")
	marked, parseErr := parseCaptureInputFaultMarkerQEMU(line)
	if err != nil || parseErr != nil || kind == "" || marked != kind {
		return nil, ErrInvalid
	}
	if err := r.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-r.gate }()
	if r.review || r.closed || r.channel == nil || r.channel.sequence != 1 || r.captureWorker == nil || r.captureWorker.file == nil {
		return nil, ErrInvalid
	}
	if err := r.checkInputs(ctx); err != nil {
		return nil, err
	}
	cover := &captureInputCoverQEMU{kind: kind}
	if kind == "channel" {
		cover.receiver = r.channel.receiver
		if err := unix.SetsockoptInt(int(cover.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 0); err != nil {
			return cover, err
		}
		return cover, nil
	}
	var original *os.File
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
	if kind == "module" {
		original = r.code.code.files[serverCaptureModuleObjectQEMU]
		cover.target = "/" + serverObserverCodePathQEMU + "/" + serverCaptureModuleObjectQEMU
	} else {
		original = r.configuration.contents.files["samba/smb.conf"]
		cover.target = "/run/phantowd-native-samba-root/etc/samba/smb.conf"
		flags |= unix.MS_NOEXEC
	}
	if original == nil {
		return nil, ErrInvalid
	}
	info, err := original.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, ErrMismatch
	}
	cover.directory, err = os.MkdirTemp("/run", "phantowd-capture-input-cover-")
	if err != nil {
		return nil, err
	}
	path := cover.directory + "/input"
	copy, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return cover, err
	}
	n, copyErr := io.Copy(copy, io.NewSectionReader(original, 0, info.Size()+1))
	if err := errors.Join(copyErr, copy.Close()); err != nil || n != info.Size() {
		return cover, errors.Join(ErrMismatch, err)
	}
	if err := os.Chmod(path, info.Mode().Perm()); err != nil {
		return cover, err
	}
	// Only the parent's prepared input path is covered. The isolated child's
	// detached original code/configuration remains held and unchanged.
	if err := unix.Mount(path, cover.target, "", unix.MS_BIND, ""); err != nil {
		return cover, err
	}
	if err := unix.Mount("", cover.target, "", unix.MS_REMOUNT|unix.MS_BIND|flags, ""); err != nil {
		return cover, err
	}
	return cover, ctx.Err()
}

func (c *captureInputCoverQEMU) restoreQEMU() error {
	if c == nil {
		return ErrInvalid
	}
	if c.restoreTried {
		return c.restoreErr
	}
	c.restoreTried = true
	if c.kind == "channel" {
		c.restoreErr = unix.SetsockoptInt(int(c.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	} else {
		c.restoreErr = unix.Unmount(c.target, 0)
		if c.restoreErr == nil {
			c.restoreErr = os.RemoveAll(c.directory)
		}
	}
	return c.restoreErr
}

func captureInputDriftProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t, kind captureInputFaultKindQEMU) error {
	cover, err := newCaptureInputCoverQEMU(ctx, r, kind)
	if err != nil {
		return fmt.Errorf("input cover construction: %w", err)
	}
	if err := captureReadRefusalStopQEMU(ctx, o, r); err != nil {
		return fmt.Errorf("input refusal and producer settlement: %w", err) // No unverified restoration.
	}
	if err := cover.restoreQEMU(); err != nil {
		return fmt.Errorf("input restore: %w", err)
	}
	if err := observeRestoredCaptureInputsQEMU(ctx, r); err != nil {
		return fmt.Errorf("restored input fence: %w", err)
	}
	if err := captureRetainedReviewProofQEMU(ctx, o, r, original, initial); err != nil {
		return fmt.Errorf("retained review: %w", err)
	}
	return nil
}

// Fixture-only point-in-time observation AFTER verified containment. The code
// keeper's review latch is not a metadata mismatch and must NEVER be cleared.
// This deliberately grants no revalidation/admission/execution authority.
func observeRestoredCaptureInputsQEMU(ctx context.Context, r *serverObserverRuntimeQEMU) error {
	if ctx == nil || r == nil || serverObserverCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if !r.review || r.closed || r.code == nil || r.code.code == nil || r.configuration == nil || r.state == nil || r.channel == nil {
		return ErrReviewRequired
	}
	codeReview := r.code.review
	if err := r.channel.endpoints(true); err != nil || !r.channel.queueEmpty() {
		return ErrMismatch
	}
	if err := r.code.binding(ctx); err != nil {
		return err
	}
	if err := r.code.code.revalidate(ctx); err != nil {
		return err
	}
	if err := r.code.binding(ctx); err != nil {
		return err
	}
	if err := r.configuration.revalidate(ctx); err != nil {
		return err
	}
	if err := r.state.revalidate(ctx); err != nil {
		return err
	}
	for i, root := range r.shares {
		if root == nil {
			return ErrInvalid
		}
		identity, err := serverObserverShareIdentityQEMU(root, i == 0)
		if err != nil || identity != r.shareIdentity[i] {
			return errors.Join(ErrMismatch, err)
		}
	}
	if err := r.channel.endpoints(true); err != nil || !r.channel.queueEmpty() || !r.review || r.code.review != codeReview {
		return ErrMismatch
	}
	return ctx.Err()
}

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
	"strconv"
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
		if kind != "" || (value != "module" && value != "configuration" && value != "channel" && value != "source" && value != "source-root") {
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

func newCaptureInputCoverQEMU(ctx context.Context, r *serverObserverRuntimeQEMU, kind captureInputFaultKindQEMU, originalData *os.File) (*captureInputCoverQEMU, error) {
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
	if kind == "source-root" {
		// Cover the fixed parent mount with the SAME original directory.
		// Bytes/device/inode remain equal, but unique mount identity changes.
		// The already-detached worker must retain its original mount/object.
		cover.target = "/run/observer-readonly"
		if err := recheckCaptureShareBindingQEMU(ctx, r.code.anchor, r.shares[0], r.shareIdentity[0]); err != nil {
			return nil, err
		}
		if err := unix.Mount("/proc/self/fd/"+strconv.FormatUint(uint64(r.shares[0].Fd()), 10), cover.target, "", unix.MS_BIND, ""); err != nil {
			return cover, err
		}
		if err := unix.Mount("", cover.target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			return cover, err
		}
		fd, err := unix.Open(cover.target, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return cover, err
		}
		changed, statErr := serverObserverRootIdentityFromFDQEMU(fd)
		closeErr := unix.Close(fd)
		expected := r.shareIdentity[0]
		if statErr != nil || closeErr != nil || changed.deviceMajor != expected.deviceMajor || changed.deviceMinor != expected.deviceMinor || changed.inode != expected.inode || changed.mount == expected.mount {
			return cover, errors.Join(ErrMismatch, statErr, closeErr)
		}
		return cover, ctx.Err()
	}
	var original *os.File
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
	if kind == "module" {
		original = r.code.code.files[serverCaptureModuleObjectQEMU]
		cover.target = "/" + serverObserverCodePathQEMU + "/" + serverCaptureModuleObjectQEMU
	} else if kind == "configuration" {
		original = r.configuration.contents.files["samba/smb.conf"]
		cover.target = "/run/phantowd-native-samba-root/etc/samba/smb.conf"
		flags |= unix.MS_NOEXEC
	} else if kind == "source" {
		// Borrow the already-held original ONLY to clone synthetic fixture
		// bytes. Never reopen/adopt the covered alias as data authority.
		original = originalData
		cover.target = "/run/observer-readonly/capture-read"
		flags |= unix.MS_NOEXEC
		var held, pinned, named unix.Stat_t
		if original == nil || unix.Fstat(int(original.Fd()), &held) != nil || unix.Fstat(int(r.captureWorker.file.Fd()), &pinned) != nil || unix.Lstat(cover.target, &named) != nil || !samePendingObjectQEMU(held, pinned) || !samePendingObjectQEMU(held, named) || held.Mode != unix.S_IFREG|0444 || held.Uid != 65534 || held.Gid != 65534 || held.Nlink != 1 || held.Size != 4 {
			return nil, ErrMismatch
		}
	} else {
		return nil, ErrInvalid
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
	if kind == "source" {
		if err := os.Chown(path, 65534, 65534); err != nil {
			return cover, err
		}
	}
	// Only the parent's prepared input path is covered. The isolated child's
	// detached original code/configuration remains held and unchanged.
	if err := unix.Mount(path, cover.target, "", unix.MS_BIND, ""); err != nil {
		return cover, err
	}
	if err := unix.Mount("", cover.target, "", unix.MS_REMOUNT|unix.MS_BIND|flags, ""); err != nil {
		return cover, err
	}
	if kind == "source" {
		var held, named unix.Stat_t
		if unix.Fstat(int(original.Fd()), &held) != nil || unix.Lstat(cover.target, &named) != nil || (held.Dev == named.Dev && held.Ino == named.Ino) || named.Mode != held.Mode || named.Uid != held.Uid || named.Gid != held.Gid || named.Size != held.Size || named.Nlink != held.Nlink {
			return cover, ErrMismatch
		}
		copy, err := os.Open(cover.target)
		if err != nil {
			return cover, err
		}
		data, readErr := io.ReadAll(io.LimitReader(copy, 5))
		if err := errors.Join(readErr, copy.Close()); err != nil || string(data) != "data" {
			return cover, errors.Join(ErrMismatch, err)
		}
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
		if c.restoreErr == nil && c.directory != "" {
			c.restoreErr = os.RemoveAll(c.directory)
		}
	}
	return c.restoreErr
}

func captureInputDriftProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t, kind captureInputFaultKindQEMU) error {
	cover, err := newCaptureInputCoverQEMU(ctx, r, kind, original)
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
	if kind == "source" || kind == "source-root" {
		// Point-in-time metadata only after verified stop; never clear review
		// or resume from a path that happens to look restored.
		if err := recheckCaptureShareBindingQEMU(ctx, r.code.anchor, r.shares[0], r.shareIdentity[0]); err != nil {
			return fmt.Errorf("restored parent share observation: %w", err)
		}
		if err := recheckCaptureSourceQEMU(ctx, r.shares[0], original, initial); err != nil {
			return fmt.Errorf("restored parent source observation: %w", err)
		}
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

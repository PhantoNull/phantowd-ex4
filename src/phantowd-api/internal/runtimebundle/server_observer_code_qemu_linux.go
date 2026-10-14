//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const serverObserverCodePathQEMU = "run/phantowd-samba-code"

// A private input lifetime, not a process Owner or execution token. Its future
// containing Owner must serialize revalidation and prove whole-group absence
// before release. Expected bytes come from an independent fixture Plan.
type serverObserverCodeQEMU struct {
	code       *retainedCode
	anchor     *os.File
	anchorID   serverObserverRootIdentityQEMU
	review     bool
	releaseErr error
}

type serverObserverRootIdentityQEMU struct {
	deviceMajor, deviceMinor uint32
	inode, mount             uint64
}

func serverObserverRootIdentityFromFDQEMU(fd int) (serverObserverRootIdentityQEMU, error) {
	var stat unix.Statx_t
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &stat) != nil ||
		stat.Mask&required != required || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Ino == 0 || stat.Mnt_id == 0 {
		return serverObserverRootIdentityQEMU{}, ErrMismatch
	}
	return serverObserverRootIdentityQEMU{stat.Dev_major, stat.Dev_minor, stat.Ino, stat.Mnt_id}, nil
}

func serverObserverCodeGuardQEMU() error {
	if runtime.GOARCH != "arm" || sambaCodeFixtureGuard() != nil {
		return ErrInvalid
	}
	commandLine, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(commandLine) > 4096 {
		return ErrInvalid
	}
	for _, field := range strings.Fields(string(commandLine)) {
		if field == "phantowd_observer_daemon_fixture=1" {
			return nil
		}
	}
	return ErrInvalid
}

func retainServerObserverCodeQEMU(ctx context.Context, plan *Plan, root *os.File) (retained *serverObserverCodeQEMU, result error) {
	if ctx == nil || plan == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := serverObserverCodeGuardQEMU(); err != nil {
		return nil, err
	}
	o := &serverObserverCodeQEMU{}
	defer func() {
		if result != nil {
			if closeErr := o.release(); closeErr != nil {
				o.review = true
				retained = o
				result = errors.Join(ErrReviewRequired, result, closeErr)
			}
		}
	}()
	var err error
	o.code, err = plan.prepareRetainedCode(ctx, root)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	o.anchor = os.NewFile(uintptr(fd), "original-observer-path-anchor")
	o.anchorID, err = serverObserverRootIdentityFromFDQEMU(fd)
	if err != nil {
		return nil, err
	}
	// Always fence after both independent references have been collected.
	if err := o.revalidate(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *serverObserverCodeQEMU) revalidate(ctx context.Context) error {
	if ctx == nil || o == nil || o.code == nil || o.anchor == nil {
		return ErrInvalid
	}
	if o.review || o.releaseErr != nil {
		return ErrReviewRequired
	}
	if err := o.binding(ctx); err != nil {
		o.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	if err := o.code.revalidate(ctx); err != nil {
		o.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	// Path binding is checked again after the complete original census/hash
	// pass, never substituted for that pass or used to adopt a replacement.
	if err := o.binding(ctx); err != nil {
		o.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	return nil
}

func (o *serverObserverCodeQEMU) binding(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	anchor, err := serverObserverRootIdentityFromFDQEMU(int(o.anchor.Fd()))
	if err != nil || anchor != o.anchorID {
		return ErrMismatch
	}
	// An old root descriptor must not authorize execution from a changed
	// namespace/chroot. Reopen the current root and compare original identity.
	current, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrMismatch
	}
	currentID, statErr := serverObserverRootIdentityFromFDQEMU(current)
	closeErr := unix.Close(current)
	if statErr != nil || closeErr != nil || currentID != o.anchorID {
		return errors.Join(ErrMismatch, statErr, closeErr)
	}
	fd, err := unix.Openat2(int(o.anchor.Fd()), serverObserverCodePathQEMU, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		// This fixed path crosses the prepared code mount intentionally; the
		// unique original mount ID is checked below, not accepted by pathname.
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return ErrMismatch
	}
	bound, statErr := serverObserverRootIdentityFromFDQEMU(fd)
	closeErr = unix.Close(fd)
	original := o.code.metadata["."]
	expected := serverObserverRootIdentityQEMU{original.Dev_major, original.Dev_minor, original.Ino, original.Mnt_id}
	if statErr != nil || closeErr != nil || bound != expected {
		return errors.Join(ErrMismatch, statErr, closeErr)
	}
	return ctx.Err()
}

// No process is owned here. Only the containing Owner may call this after
// verified settlement; uncertainty preserves the first error and unattempted
// originals. Failed Close does not establish that its descriptor remains open.
func (o *serverObserverCodeQEMU) release() error {
	if o == nil {
		return nil
	}
	if o.releaseErr != nil {
		return o.releaseErr
	}
	if err := o.code.release(); err != nil {
		o.releaseErr = err
		return err
	}
	if o.anchor != nil {
		if err := o.anchor.Close(); err != nil {
			o.releaseErr = err
			return err
		}
		o.anchor = nil
	}
	return nil
}

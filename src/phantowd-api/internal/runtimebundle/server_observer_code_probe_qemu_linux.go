//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ProbeServerObserverCodeBindingQEMU uses only the explicitly guarded guest's
// disposable RAM code tree. No process is launched and no references escape.
// The exact-byte copy is an independent negative control, never adopted inputs.
func (p *Plan) ProbeServerObserverCodeBindingQEMU(ctx context.Context, root, source *os.File) (result error) {
	if ctx == nil || p == nil || root == nil || source == nil {
		return ErrInvalid
	}
	if err := serverObserverCodeGuardQEMU(); err != nil {
		return err
	}
	caller, err := duplicateRoot(root)
	if err != nil {
		return err
	}
	code, err := retainServerObserverCodeQEMU(ctx, p, caller)
	callerErr := caller.Close()
	if err != nil || callerErr != nil {
		return errors.Join(err, callerErr, code.release())
	}
	defer func() { result = errors.Join(result, code.release()) }()
	if err := code.revalidate(ctx); err != nil {
		return err
	}
	// Clone into bounded existing /run tmpfs, seal and independently inspect.
	copyPath, err := os.MkdirTemp("/run", "observer-code-copy-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(copyPath)) }()
	fd, err := unix.Open(copyPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	copyRoot := os.NewFile(uintptr(fd), "disposable-observer-code-copy")
	defer func() { result = errors.Join(result, copyRoot.Close()) }()
	if err := p.StageQEMU(ctx, source, copyRoot); err != nil {
		return err
	}
	if err := unix.Mount(copyPath, copyPath, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(copyPath, 0)) }()
	if err := unix.Mount("", copyPath, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	// The pre-bind descriptor is a writable staging view, never admitted code.
	sealedFD, err := unix.Open(copyPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	sealed := os.NewFile(uintptr(sealedFD), "independent-sealed-code-copy")
	defer func() { result = errors.Join(result, sealed.Close()) }()
	if _, err := p.Inspect(ctx, sealed); err != nil {
		return errors.Join(errors.New("copy census/hash positive control"), err)
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	foreign, err := retainServerObserverCodeQEMU(ctx, p, sealed)
	if foreign != nil || !errors.Is(err, ErrReviewRequired) {
		return errors.Join(errors.New("identical foreign root obtained fixed-path inputs"), err, foreign.release())
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.Join(errors.New("foreign-root refusal leaked references"), err)
	}
	if _, err := sealed.Stat(); err != nil {
		return errors.Join(errors.New("foreign-root refusal consumed caller"), err)
	}
	// Overmount ONLY the fixed test-owned code path. Original pins retain the
	// hidden mount; their complete original census still passes independently.
	if err := unix.Mount(copyPath, "/"+serverObserverCodePathQEMU, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	covered := true
	defer func() {
		if covered {
			result = errors.Join(result, unix.Unmount("/"+serverObserverCodePathQEMU, 0))
		}
	}()
	if err := code.code.revalidate(ctx); err != nil {
		return errors.Join(errors.New("original retained census positive control"), err)
	}
	if err := code.revalidate(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.Join(errors.New("identical copied root replaced fixed original binding"), err)
	}
	for _, pin := range code.code.files {
		if _, err := pin.Stat(); err != nil {
			return errors.Join(errors.New("refusal consumed original code"), err)
		}
	}
	if _, err := code.anchor.Stat(); err != nil {
		return err
	}
	if err := unix.Unmount("/"+serverObserverCodePathQEMU, 0); err != nil {
		return err
	}
	covered = false
	if err := code.code.revalidate(ctx); err != nil {
		return errors.Join(errors.New("restored original census positive control"), err)
	}
	if err := code.revalidate(ctx); !errors.Is(err, ErrReviewRequired) {
		return errors.New("restoration cleared original-code review")
	}
	if err := code.release(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SERVER_OBSERVER_CODE_BINDING_PROOF complete_original_census=true caller_close=true foreign_root_refused=true identical_copy_refused=true originals_retained=true restoration_refused=true released=true scope=qemu-only")
	return nil
}

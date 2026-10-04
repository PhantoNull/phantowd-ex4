//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// WithQEMUMountedSetLoss exposes only this guest's fixed disposable roster and
// a single same-source bind injection/restoration. The callback must prove
// quarantine; restoring the mount is fixture cleanup, never Owner recovery.
func WithQEMUMountedSetLoss(source string, inspect func(*MountedVolumeSet, func() error, func() error) error) error {
	if inspect == nil {
		return errors.New("mounted loss fixture requires an observer")
	}
	err := withQEMUMountedOwner(source, func(owner *Owner) (result error) {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return err
		}
		observer := linuxObserver{}
		before, err := observer.ObserveTarget(owner.target)
		if err != nil {
			return err
		}
		var replacement TargetIdentity
		injected, mounted, restored := false, false, false
		restore := func() error {
			if !mounted || restored {
				return errors.New("mount-loss restoration is not repeatable")
			}
			current, err := observer.ObserveTarget(owner.target)
			if err != nil || current != replacement {
				return errors.Join(errors.New("mount-loss fixture target changed before cleanup"), err)
			}
			if err := unix.Unmount(owner.target, 0); err != nil {
				return err
			}
			mounted = false
			current, err = observer.ObserveTarget(owner.target)
			if err != nil || current != before {
				return errors.Join(errors.New("mount-loss fixture did not restore its exact original bind"), err)
			}
			restored = true
			return nil
		}
		defer func() {
			if mounted {
				result = errors.Join(result, restore())
			}
		}()
		lose := func() error {
			if injected || owner.Verify() != nil {
				return errors.New("mount-loss injection requires its original healthy bind")
			}
			injected = true
			if err := unix.Mount(source, owner.target, "", unix.MS_BIND, ""); err != nil {
				return err
			}
			mounted = true
			replacement, err = observer.ObserveTarget(owner.target)
			if err != nil || replacement.MountID == before.MountID ||
				replacement.RootInode != before.RootInode || replacement.DeviceMajor != before.DeviceMajor ||
				replacement.DeviceMinor != before.DeviceMinor || replacement.FilesystemType != before.FilesystemType {
				return errors.Join(errors.New("mount-loss fixture requires a new mount identity on the same filesystem/root"), err)
			}
			return nil
		}
		if err := inspect(set, lose, restore); err != nil {
			return err
		}
		if !injected || !restored || mounted || owner.State() != StateReviewRequired {
			return errors.New("mount-loss fixture did not complete quarantine and exact restoration")
		}
		return errQEMUExpectedMountedOwnerReview
	})
	// Only the exact sentinel after complete teardown succeeds. Joined cleanup
	// failures must not be hidden by errors.Is or by an expected reviewed state.
	if err != errQEMUExpectedMountedOwnerReview {
		return errors.Join(errors.New("mounted loss fixture failed exact teardown"), err)
	}
	return nil
}

// RunQEMURootPinLossFixture changes only a fixed disposable guest bind mount.
// It proves metadata lifetime retention, not a product writer or recovery path.
func RunQEMURootPinLossFixture(source string) error {
	err := withQEMUMountedOwner(source, func(owner *Owner) (result error) {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return err
		}
		lease, _, err := set.Acquire(context.Background())
		if err != nil {
			return err
		}
		defer func() {
			if err := lease.Close(); err != nil {
				result = errors.Join(result, err)
			}
		}()
		pin, err := lease.PinVolumeRoot(qemuPlannerVolumeID)
		if err != nil {
			return err
		}
		defer func() {
			if err := pin.Release(); err != nil {
				result = errors.Join(result, err)
			}
		}()
		directory, err := pin.OpenDirectory(".")
		if err != nil {
			return err
		}
		defer func() {
			if err := directory.Close(); err != nil {
				result = errors.Join(result, err)
			}
		}()
		if err := lease.Close(); !errors.Is(err, ErrBusy) {
			return errors.New("live root pin did not block group close")
		}
		// Same filesystem/root, different kernel mount ID: identity must not be
		// inferred from UUID or inode equality. Fixture teardown removes both
		// bind layers only after independent references and claims are released.
		if err := unix.Mount(source, owner.target, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if err := pin.Verify(); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
			return errors.New("actual overmount did not quarantine root pin")
		}
		if err := lease.Close(); !errors.Is(err, ErrBusy) {
			return errors.New("quarantine released the pinned group")
		}
		if _, err := directory.Stat(); err != nil {
			return errors.New("review lost the independent root descriptor")
		}
		return errQEMUExpectedMountedOwnerReview
	})
	// An added close/teardown failure must never masquerade as expected review.
	if err != errQEMUExpectedMountedOwnerReview {
		return errors.Join(errors.New("root-pin loss fixture failed exact teardown"), err)
	}
	fmt.Println("PHANTOWD_ROOT_PIN_LOSS_READY actual_mount_identity_loss=true independent_fd_retained=true caller_lease_close_busy=true release_before_fixture_unmount=true product_recovery=false scope=disposable-qemu-only")
	return nil
}

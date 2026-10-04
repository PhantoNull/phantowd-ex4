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

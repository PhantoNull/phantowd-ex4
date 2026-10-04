//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"golang.org/x/sys/unix"
)

// Fixed disposable fixture; real bind/mount qualification remains owned by
// mountowner's QEMU-only helper. No production roster, data opener or LIO.
func RunQEMUMountedWritableFixture(source string) error {
	err := mountowner.WithQEMUMountedSet(source, func(set *mountowner.MountedVolumeSet) (result error) {
		const anchor = "/srv/phantowd/volumes/qemu-plan"
		workspace, err := os.MkdirTemp(anchor, "mounted-backing-")
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, os.RemoveAll(workspace)) }()
		lease, _, err := set.Acquire(context.Background())
		if err != nil {
			return err
		}
		// Failed metadata admission must not strand a healthy mount lifetime.
		pin, _, openErr := OpenFromMountedLease(lease, "qemu-plan", filepath.Base(workspace)+"/missing", 4096)
		if pin != nil || !errors.Is(openErr, ErrUnavailable) {
			if pin != nil {
				_ = pin.Close()
			}
			_ = lease.Close()
			return errors.New("missing mounted backing was admitted")
		}
		if err := lease.Close(); err != nil {
			return fmt.Errorf("failed mounted backing retained a healthy lease: %w", err)
		}
		for _, kind := range []string{"normal", "replace", "exit", "uncertain"} {
			if err := mountedWritableCase(set, workspace, kind); err != nil {
				return fmt.Errorf("mounted writable %s: %w", kind, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, uncertain := range []bool{false, true} {
		if err := mountedWritableLossCase(source, uncertain); err != nil {
			return fmt.Errorf("mounted writable loss uncertain=%t: %w", uncertain, err)
		}
	}
	fmt.Println("PHANTOWD_MOUNTED_WRITER_LOSS_READY actual_same_fs_overmount=true consumer_uid=1000 stop_before_release=true uncertain_stop_retains_mount=true restoration_no_revival=true no_retry=true exact_fixture_teardown=true product_recovery=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_MOUNTED_BACKING_READY real_mount_owner=true exact_roster=true caller_lease_close_busy=true repeated_verify_no_fd_growth=true stop_before_mount_release=true uncertain_stop_retains_mount=true product_opener=false iscsi_backend=false scope=disposable-qemu-only")
	return nil
}

func mountedWritableCase(set *mountowner.MountedVolumeSet, workspace, kind string) (result error) {
	return withMountedWritableCase(set, workspace, kind, func(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend, file string, lease *mountowner.MountedVolumeSetLease) error {
		return exerciseWritableOwnerFixture(ctx, owner, backend, file, kind, lease)
	})
}

// Private QEMU-only composition; existing normal and loss cases share setup.
func withMountedWritableCase(set *mountowner.MountedVolumeSet, workspace, kind string, exercise func(context.Context, *writableOwner, *fixtureWritableBackend, string, *mountowner.MountedVolumeSetLease) error) (result error) {
	lease, _, err := set.Acquire(context.Background())
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	file := workspace + "/" + kind
	if err := os.WriteFile(file, make([]byte, 4096), 0600); err != nil {
		return err
	}
	pin, _, err := OpenFromMountedLease(lease, "qemu-plan", filepath.Base(workspace)+"/"+kind, 4096)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, pin.Close()) }()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for sample := 0; sample < 32; sample++ {
		if _, err := pin.Verify(); err != nil {
			return err
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return errors.New("mounted metadata verification leaked descriptors")
	}
	fd, err := unix.Open(file, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	data := os.NewFile(uintptr(fd), "mounted-qemu-writable-file")
	backend := &fixtureWritableBackend{}
	owner, err := newWritableOwner(pin, data, backend)
	if err != nil {
		data.Close()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer func() {
		// Independent disposable-fixture cleanup only, never Owner recovery.
		pin.mu.Lock()
		claimed := pin.consumer == owner
		pin.mu.Unlock()
		if !owner.released && claimed {
			if err := backend.teardown(ctx); err != nil {
				result = errors.Join(result, err)
				return
			}
			if err := data.Close(); err != nil {
				result = errors.Join(result, err)
				return // Preserve the claim if descriptor closure is uncertain.
			}
			pin.mu.Lock()
			pin.consumer = nil
			result = errors.Join(result, pin.closeLocked())
			pin.mu.Unlock()
		}
	}()
	return exercise(ctx, owner, backend, file, lease)
}

func mountedWritableLossCase(source string, uncertain bool) error {
	return mountowner.WithQEMUMountedSetLoss(source, func(set *mountowner.MountedVolumeSet, lose, restore func() error) (result error) {
		workspace, err := os.MkdirTemp("/srv/phantowd/volumes/qemu-plan", "mounted-loss-")
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, os.RemoveAll(workspace)) }()
		return withMountedWritableCase(set, workspace, "loss", func(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend, file string, lease *mountowner.MountedVolumeSetLease) error {
			if err := owner.start(ctx); err != nil {
				return err
			}
			if err := owner.observe(ctx); err != nil {
				return err
			}
			if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
				return errors.New("live mounted loss consumer did not retain lease")
			}
			backend.stopFailure = uncertain
			if err := lose(); err != nil {
				return err
			}
			if err := owner.observe(ctx); !errors.Is(err, ErrReview) || owner.phase != writableReview {
				return errors.New("actual mount loss did not quarantine consumer")
			}
			if backend.stopCalls != 1 || !backend.stopWithLiveReference {
				return errors.New("mount loss did not stop once with retained RW reference")
			}
			if uncertain {
				if owner.released || owner.pin.consumer != owner {
					return errors.New("uncertain mount loss released consumer references")
				}
				if err := owner.pin.Close(); !errors.Is(err, ErrBusy) {
					return errors.New("uncertain mount loss allowed Pin close")
				}
				if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
					return errors.New("uncertain mount loss allowed mount release")
				}
				if _, err := owner.file.Stat(); err != nil {
					return errors.New("uncertain mount loss lost RW descriptor")
				}
				if running, err := backend.running(ctx); err != nil || !running {
					return errors.New("uncertain fixture must retain an actual live consumer")
				}
			} else {
				if !owner.released || owner.file != nil {
					return errors.New("confirmed mount-loss stop did not release references")
				}
				select {
				case <-backend.done:
				default:
					return errors.New("mount-loss release preceded confirmed child reap")
				}
				if err := lease.Close(); err != nil {
					return err
				}
			}
			if err := restore(); err != nil {
				return err
			}
			for _, op := range []func() error{func() error { return owner.observe(ctx) }, func() error { return owner.start(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
				if err := op(); !errors.Is(err, ErrReview) {
					return errors.New("mount restoration revived reviewed consumer")
				}
			}
			if backend.stopCalls != 1 {
				return errors.New("mount restoration retried uncertain stop")
			}
			if uncertain {
				if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
					return errors.New("restoration bypassed uncertain retained mount")
				}
				if _, err := owner.file.Stat(); err != nil || owner.released {
					return errors.New("restoration discarded uncertain data reference")
				}
			}
			if fresh, _, err := set.Acquire(ctx); fresh != nil || !errors.Is(err, mountowner.ErrReview) {
				if fresh != nil {
					_ = fresh.Close()
				}
				return errors.New("restored reviewed mount issued a new lease")
			}
			data, err := os.ReadFile(file)
			if err != nil || len(data) != 4096 || string(data[:len(writableFixtureData)]) != writableFixtureData {
				return errors.Join(errors.New("same-filesystem mount loss lost original backing data"), err)
			}
			// Shared fixture cleanup independently reaps an uncertain child,
			// closes its references, then releases the reviewed lease. It never
			// clears review or implements product recovery.
			return nil
		})
	})
}

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
	fmt.Println("PHANTOWD_MOUNTED_BACKING_READY real_mount_owner=true exact_roster=true caller_lease_close_busy=true repeated_verify_no_fd_growth=true stop_before_mount_release=true uncertain_stop_retains_mount=true product_opener=false iscsi_backend=false scope=disposable-qemu-only")
	return nil
}

func mountedWritableCase(set *mountowner.MountedVolumeSet, workspace, kind string) (result error) {
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
		if !owner.released && claimed && backend.teardown(ctx) == nil {
			_ = data.Close()
			pin.mu.Lock()
			pin.consumer = nil
			result = errors.Join(result, pin.closeLocked())
			pin.mu.Unlock()
		}
	}()
	return exerciseWritableOwnerFixture(ctx, owner, backend, file, kind, lease)
}

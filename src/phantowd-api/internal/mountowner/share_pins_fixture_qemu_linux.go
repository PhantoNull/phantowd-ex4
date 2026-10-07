//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Called only after RunQEMUIsolatedHandoffFixture's exact guest/root guard.
// Data and mount operations are confined to its generated ext2 fixture.
func exerciseQEMUSharePins() (result error) {
	for _, name := range []string{"pinned-rw", "pinned-ro"} {
		path := qemuFixtureSource + "/" + name
		if err := os.Mkdir(path, 0770); err != nil {
			return err
		}
		defer os.Remove(path)
		if err := errors.Join(os.Chown(path, 1000, 1000), os.Chmod(path, 0770)); err != nil {
			return err
		}
	}
	defer os.Remove(qemuFixtureSource + "/pinned-rw/created")
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, loss := range []bool{false, true} {
		if err := exerciseQEMUSharePinsAt(loss); err != nil {
			return err
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return errors.New("declared share pin fixture leaked descriptors")
	}
	fmt.Println("PHANTOWD_DECLARED_SHARE_PINS_READY roots=2 original_objects=true caller_close=true writable_nonroot=true readonly_EROFS=true mutable_data=true handoff_close_gated=true source_loss_review=true restoration_refused=true descriptor_equality=true samba_access=false scope=disposable-qemu-only")
	return nil
}

func exerciseQEMUSharePinsAt(loss bool) (result error) {
	const root = "/run/phantowd/service-handoff/share-pins-qemu"
	if err := os.Mkdir(root, 0710); err != nil {
		return err
	}
	defer os.Remove(root)
	if err := errors.Join(os.Chown(root, 0, 1000), os.Chmod(root, 0710)); err != nil {
		return err
	}
	result = withQEMUMountedOwner(qemuFixtureSource, func(owner *Owner) (result error) {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return err
		}
		h, err := NewServiceHandoff(root, set, []ServiceShare{
			{ID: "writable", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-rw"},
			{ID: "readonly", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-ro", ReadOnly: true},
		}, 1000)
		if err != nil {
			return err
		}
		if _, err := h.Mount(context.Background()); err != nil {
			return err
		}
		pins, err := h.RetainShareRootsQEMU()
		if err != nil {
			return err // Retain any non-nil quarantined handle; no teardown retry.
		}
		if duplicate, err := h.RetainShareRootsQEMU(); duplicate != nil || !errors.Is(err, ErrHandoffReview) {
			return errors.New("handoff issued two independently releasable consumers")
		}
		if !errors.Is(h.Close(), ErrHandoffBusy) {
			return errors.New("retained share roots did not block handoff close")
		}
		for iteration := 0; iteration < 2; iteration++ {
			inputs, err := pins.DuplicateRoots()
			if err != nil || len(inputs) != 2 || inputs[0].ShareID != "readonly" || !inputs[0].ReadOnly ||
				inputs[1].ShareID != "writable" || inputs[1].ReadOnly {
				return errors.New("share descriptor set lost exact declared roles")
			}
			for _, input := range inputs {
				if err := exerciseQEMUShareInput(input); err != nil {
					return err
				}
				if err := input.File.Close(); err != nil {
					return err
				}
			}
			if err := pins.Verify(); err != nil {
				return errors.New("caller close or legitimate data write invalidated original pins")
			}
		}
		if loss {
			if err := unix.Mount("/run", owner.target, "", unix.MS_BIND, ""); err != nil {
				return err
			}
			if !errors.Is(pins.Verify(), ErrHandoffReview) || !errors.Is(h.Close(), ErrHandoffBusy) {
				return errors.New("source loss did not retain reviewed share authority")
			}
			if err := unix.Unmount(owner.target, 0); err != nil {
				return err
			}
			if inputs, err := pins.DuplicateRoots(); inputs != nil || !errors.Is(err, ErrHandoffReview) {
				return errors.New("source restoration revived a reviewed share input")
			}
		}
		closeErr := pins.Close() // All synthetic clients exited; copied inputs closed.
		if (!loss && closeErr != nil) || (loss && !errors.Is(closeErr, ErrHandoffReview)) ||
			!errors.Is(pins.Verify(), ErrHandoffUnavailable) {
			return errors.New("settled input close did not release exactly once")
		}
		handoffErr := h.Close()
		if loss {
			if !errors.Is(handoffErr, ErrHandoffReview) || !h.resourcesClosed {
				return errors.New("reviewed share handoff did not detach settled exact clones")
			}
			return errQEMUExpectedMountedOwnerReview
		}
		return handoffErr
	})
	if result == errQEMUExpectedMountedOwnerReview {
		return nil
	}
	return result
}

func exerciseQEMUShareInput(input ServiceShareDescriptorQEMU) error {
	// Fixed synthetic operation under a distinct non-root Unix identity; no
	// caller-supplied program, path, credential or command reaches this fixture.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "printf qualified > /proc/self/fd/3/created")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{}}}
	command.ExtraFiles = []*os.File{input.File}
	command.WaitDelay = time.Second
	err := command.Run()
	if input.ReadOnly {
		if err == nil || ctx.Err() != nil {
			return errors.New("non-root client wrote to a read-only declared share")
		}
		fd, openErr := unix.Openat(int(input.File.Fd()), "created", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if !errors.Is(openErr, unix.EROFS) {
			return errors.New("read-only refusal was not enforced by the kernel mount")
		}
		return nil
	}
	if err != nil {
		return errors.New("non-root client could not write to its declared writable share")
	}
	var st unix.Stat_t
	if unix.Fstatat(int(input.File.Fd()), "created", &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 1000 || st.Gid != 1000 || st.Size != 9 {
		return errors.New("synthetic share write lost effective Unix ownership")
	}
	return nil
}

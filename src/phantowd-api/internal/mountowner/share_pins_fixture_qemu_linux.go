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
	"slices"
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
	if err := exerciseQEMUSharePinCloseFailure(); err != nil {
		return err
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return errors.New("declared share pin fixture leaked descriptors")
	}
	fmt.Println("PHANTOWD_DECLARED_SHARE_PINS_READY roots=2 original_objects=true caller_close=true writable_nonroot=true readonly_EROFS=true mutable_data=true handoff_close_gated=true source_loss_review=true restoration_refused=true descriptor_equality=true samba_access=false scope=disposable-qemu-only")
	return nil
}

// Actual qualified mount/handoff inputs, with no child or external alias left
// alive. Premature closure is a controlled guest-only fault, not kernel EIO.
func exerciseQEMUSharePinCloseFailure() (result error) {
	const root = "/run/phantowd/service-handoff/share-pin-close-qemu"
	if err := os.Mkdir(root, 0710); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.Remove(root)) }()
	if err := errors.Join(os.Chown(root, 0, 1000), os.Chmod(root, 0710)); err != nil {
		return err
	}
	return withQEMUMountedOwner(qemuFixtureSource, func(owner *Owner) (result error) {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return err
		}
		declaration := []ServiceShare{
			{ID: "readonly", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-ro", ReadOnly: true},
			{ID: "writable", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-rw"},
		}
		h, err := NewServiceHandoff(root, set, declaration, 1000)
		if err != nil {
			return err
		}
		if _, err := h.Mount(context.Background()); err != nil {
			return err
		}
		pins, err := h.RetainShareRootsQEMU()
		if err != nil {
			return err // Never retry an uncertain partial retention.
		}
		// No daemon is constructed and no descriptor is exported by this case.
		// Independent exact-object disposal below never uses public Close to
		// release reviewed resources, resets review/reservations or claims recovery.
		defer func() { result = errors.Join(result, disposeQEMUSharePinCloseFixture(pins)) }()
		if pins.Verify() != nil || pins.VerifyDeclaredRoots(declaration) != nil ||
			len(pins.roots) != 2 || len(h.members) != 2 || h.lease == nil {
			return errors.New("close-fault fixture did not retain healthy original mounted shares")
		}
		original, later := pins.roots[0].file, pins.roots[1].file
		if err := original.Close(); err != nil {
			return err
		}
		if !errors.Is(pins.Close(), ErrHandoffReview) || h.State() != ServiceHandoffReview {
			return errors.New("actual mounted original close failure did not preserve review")
		}
		for range 3 {
			if !errors.Is(pins.Close(), ErrHandoffReview) ||
				!errors.Is(pins.Verify(), ErrHandoffReview) ||
				!errors.Is(pins.VerifyDeclaredRoots(declaration), ErrHandoffReview) ||
				!errors.Is(h.Close(), ErrHandoffBusy) {
				return errors.New("actual mounted close uncertainty revived use or teardown")
			}
			if copies, err := pins.DuplicateRoots(); copies != nil || !errors.Is(err, ErrHandoffReview) {
				return errors.New("actual close uncertainty issued new share descriptors")
			}
			// A handoff already in review is unavailable to fresh admission;
			// that pre-existing public error differs from the pin's review error.
			if next, err := h.RetainShareRootsQEMU(); next != nil || !errors.Is(err, ErrHandoffUnavailable) ||
				h.State() != ServiceHandoffReview {
				return errors.New("reviewed handoff admitted replacement share pins or lost review")
			}
			if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
				return errors.New("original premature closure was not real")
			}
			if _, err := later.Stat(); err != nil {
				return errors.New("uncertain close touched the later original share")
			}
			if _, err := h.lease.Verify(); err != nil || owner.Verify() != nil ||
				owner.State() != StateMounted || h.resourcesClosed {
				return errors.New("uncertain close released the actual mounted roster")
			}
			for _, member := range h.members {
				observed, err := h.observeTargetLocked(member.shareID)
				if err != nil || observed != member.bound || !member.mounted {
					return errors.New("uncertain close detached an original grant mount")
				}
			}
		}
		fmt.Println("PHANTOWD_DECLARED_SHARE_CLOSE_READY actual_mount_owner=true healthy_admission=true actual_original_close_failure=true later_original_retained=true grant_mounts_retained=true roster_retained=true terminal_review=true replacement_refused=true no_close_retry=true samba_access=false recovery=false scope=disposable-qemu-only")
		return nil
	})
}

// Disposal of this fixed, never-launched test case only. Observe already-closed
// inputs instead of closing them twice; close each remaining known descriptor
// once, then detach only verified original clones. Do not alter lifetime state.
func disposeQEMUSharePinCloseFixture(pins *ServiceSharePinsQEMU) error {
	if pins == nil || pins.handoff == nil {
		return ErrHandoffInvalid
	}
	h := pins.handoff
	if h.rootPath != "/run/phantowd/service-handoff/share-pin-close-qemu" ||
		!pins.closeUncertain || h.state != ServiceHandoffReview || h.isolatedPins != 1 ||
		len(pins.roots) != 2 || len(h.members) != 2 || h.resourcesClosed {
		return ErrHandoffReview // Never become a generic force-teardown helper.
	}
	for _, root := range pins.roots {
		if root.file == nil {
			return ErrHandoffReview
		}
		if _, err := root.file.Stat(); errors.Is(err, os.ErrClosed) {
			continue
		} else if err != nil {
			return err
		}
		if err := root.file.Close(); err != nil {
			return err
		}
	}
	for index := len(h.members) - 1; index >= 0; index-- {
		member := h.members[index]
		current, err := h.observeTargetLocked(member.shareID)
		if err != nil || current != member.bound || member.uncertain || !member.mounted {
			return ErrHandoffReview
		}
		target := fmt.Sprintf("/proc/self/fd/%d/%s", h.root.Fd(), member.shareID)
		if err := unix.Unmount(target, 0); err != nil {
			return err
		}
		current, err = h.observeTargetLocked(member.shareID)
		if err != nil || current != member.targetBefore {
			return ErrHandoffReview
		}
		if err := unix.Unlinkat(int(h.root.Fd()), member.shareID, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	if err := h.lease.Close(); err != nil {
		return err
	}
	if err := h.root.Close(); err != nil {
		return err
	}
	if !errors.Is(pins.Close(), ErrHandoffReview) || !errors.Is(h.Close(), ErrHandoffBusy) ||
		h.State() != ServiceHandoffReview || h.resourcesClosed {
		return errors.New("independent fixture disposal falsely recovered reviewed authority")
	}
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
		declaration := []ServiceShare{
			{ID: "writable", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-rw"},
			{ID: "readonly", VolumeID: qemuPlannerVolumeID, RelativePath: "pinned-ro", ReadOnly: true},
		}
		if err := pins.VerifyDeclaredRoots(declaration); err != nil {
			return errors.New("exact complete declaration did not match retained share roots")
		}
		for _, field := range []string{"missing", "extra", "duplicate", "ID", "volume", "path", "RO"} {
			wrong := slices.Clone(declaration)
			switch field {
			case "missing":
				wrong = wrong[:1]
			case "extra":
				wrong = append(wrong, ServiceShare{ID: "extra"})
			case "duplicate":
				wrong[1] = wrong[0]
			case "ID":
				wrong[0].ID = "different"
			case "volume":
				wrong[0].VolumeID = "other"
			case "path":
				wrong[0].RelativePath = "replacement"
			case "RO":
				wrong[0].ReadOnly = true
			}
			if !errors.Is(pins.VerifyDeclaredRoots(wrong), ErrHandoffInvalid) || pins.Verify() != nil {
				return errors.New("different declaration matched or quarantined healthy original share pins")
			}
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
			if !errors.Is(pins.VerifyDeclaredRoots(declaration), ErrHandoffReview) {
				return errors.New("matching policy declaration revived reviewed source authority")
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

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

const (
	qemuFixtureSource = "/srv/phantowd/volumes/qemu-only"
	qemuFixtureUUID   = "11111111-2222-3333-4444-555555555555"
)

// RunQEMUFixture exercises real bind-mount operations only against the
// synthetic ext2 volume in the disposable Versatile PB QEMU guest. It is
// absent from normal builds and deliberately rejects physical EX4 hardware.
func RunQEMUFixture(source string) error {
	if source != qemuFixtureSource || runtime.GOOS != "linux" || runtime.GOARCH != "arm" {
		return errors.New("mount-owner fixture requires its fixed QEMU source")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("mount-owner fixture requires the disposable Versatile PB guest")
	}
	if err := exerciseQualifiedLifecycle(source); err != nil {
		return fmt.Errorf("qualified mount lifecycle: %w", err)
	}
	if err := exerciseChangedIdentityRevocation(source); err != nil {
		return fmt.Errorf("mount identity revocation: %w", err)
	}
	if err := exerciseAmbiguousMountResult(source); err != nil {
		return fmt.Errorf("ambiguous mount result: %w", err)
	}
	if err := exerciseAmbiguousUnmountResult(source); err != nil {
		return fmt.Errorf("ambiguous unmount result: %w", err)
	}
	if err := exerciseMismatchedMountRefusal(source); err != nil {
		return fmt.Errorf("mismatched mount refusal: %w", err)
	}
	fmt.Println("PHANTOWD_MOUNT_OWNER_READY qualified_before_lease=true identity_change_blocks_new_access=true owner_handles_revoked=true ambiguous_mount_no_retry=true ambiguous_unmount_no_retry=true mismatch_no_lease=true scope=disposable-qemu-only")
	return nil
}

type linuxObserver struct{}

func (linuxObserver) ObserveMount(path string) (mountguard.Expected, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return mountguard.Expected{}, err
	}
	defer unix.Close(fd)
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return mountguard.Expected{}, err
	}
	if st.Mask&(unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) !=
		(unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return mountguard.Expected{}, mountguard.ErrUnsupported
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return mountguard.Expected{}, err
	}
	return mountguard.Expected{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major,
		DeviceMinor: st.Dev_minor, FilesystemType: uint32(filesystem.Type),
		RequireWritable: filesystem.Flags&unix.ST_RDONLY == 0}, nil
}

func (linuxObserver) ObserveTarget(path string) (TargetIdentity, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return TargetIdentity{}, err
	}
	defer unix.Close(fd)
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE|unix.STATX_BASIC_STATS, &st); err != nil {
		return TargetIdentity{}, err
	}
	const required = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if st.Mask&required != required || st.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return TargetIdentity{}, mountguard.ErrUnsupported
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return TargetIdentity{}, err
	}
	return TargetIdentity{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major,
		DeviceMinor: st.Dev_minor, FilesystemType: uint32(filesystem.Type),
		MountRoot: st.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0, MountRootKnown: true}, nil
}

func (linuxObserver) TargetEmpty(path string) (bool, error) {
	fd, err := openPath(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return false, err
	}
	directory := os.NewFile(uintptr(fd), "mount-owner-target")
	defer directory.Close()
	entries, err := directory.ReadDir(1)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return false, mountguard.ErrUnavailable
	}
	return len(entries) == 0, nil
}

func openPath(path string, flags int) (int, error) {
	how := &unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return -1, mountguard.ErrUnavailable
	}
	return fd, nil
}

type qemuBindDriver struct {
	source             string
	target             string
	bindSourceOverride string
	loseMountResult    bool
	loseUnmountResult  bool
	mountCalls         int
	unmountCalls       int
}

func (d *qemuBindDriver) MountBind(source, target string) error {
	d.mountCalls++
	if source != d.source || target != d.target {
		return ErrInvalid
	}
	actualSource := source
	if d.bindSourceOverride != "" {
		actualSource = d.bindSourceOverride
	}
	if err := unix.Mount(actualSource, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if d.loseMountResult {
		return errors.New("fixture lost the completed bind-mount result")
	}
	return nil
}

func (d *qemuBindDriver) Unmount(target string) error {
	d.unmountCalls++
	if target != d.target {
		return ErrInvalid
	}
	if err := unix.Unmount(target, 0); err != nil {
		return err
	}
	if d.loseUnmountResult {
		return errors.New("fixture lost the completed unmount result")
	}
	return nil
}

type qemuMountFixture struct {
	owner         *Owner
	qualification *Qualification
	driver        *qemuBindDriver
	target        string
	workspace     string
	targetBefore  TargetIdentity
}

func newQEMUMountFixture(source string) (*qemuMountFixture, error) {
	workspace, err := os.MkdirTemp("/run", "phantowd-mount-owner-")
	if err != nil {
		return nil, err
	}
	target := workspace + "/target"
	if err := os.Mkdir(target, 0700); err != nil {
		os.Remove(workspace)
		return nil, err
	}
	observer := linuxObserver{}
	sourceExpected, err := observer.ObserveMount(source)
	if err != nil || sourceExpected.FilesystemType != uint32(unix.EXT4_SUPER_MAGIC) || !sourceExpected.RequireWritable {
		os.Remove(target)
		os.Remove(workspace)
		return nil, mountguard.ErrMismatch
	}
	sourceExpected.FilesystemUUID = qemuFixtureUUID
	sourceRoot, err := mountguard.Open(source, sourceExpected)
	if err != nil {
		os.Remove(target)
		os.Remove(workspace)
		return nil, err
	}
	qualification := &Qualification{volumeID: "qemu-only", source: source, expected: sourceExpected, sourceRoot: sourceRoot}
	driver := &qemuBindDriver{source: source, target: target}
	owner, err := newOwner(target, driver, observer, func(path string, expected mountguard.Expected) (rootGuard, error) {
		return mountguard.Open(path, expected)
	})
	if err != nil {
		sourceRoot.Close()
		os.Remove(target)
		os.Remove(workspace)
		return nil, err
	}
	targetBefore, err := observer.ObserveTarget(target)
	if err != nil {
		owner.Close()
		os.Remove(target)
		os.Remove(workspace)
		return nil, err
	}
	return &qemuMountFixture{owner: owner, qualification: qualification, driver: driver,
		target: target, workspace: workspace, targetBefore: targetBefore}, nil
}

func (f *qemuMountFixture) close() error {
	if f == nil {
		return nil
	}
	if err := f.owner.Close(); err != nil {
		return err
	}
	if f.qualification != nil && f.qualification.sourceRoot != nil {
		f.qualification.sourceRoot.Close()
		f.qualification.sourceRoot = nil
	}
	observer := linuxObserver{}
	// Only this fixture's exact /run target is considered. At most two bind
	// layers can exist here: the Owner bind and the explicit overmount test.
	for attempts := 0; attempts < 2; attempts++ {
		current, err := observer.ObserveTarget(f.target)
		if err != nil {
			return err
		}
		if current == f.targetBefore {
			break
		}
		if err := unix.Unmount(f.target, 0); err != nil {
			return err
		}
	}
	current, err := observer.ObserveTarget(f.target)
	if err != nil || current != f.targetBefore {
		return errors.Join(errors.New("fixture target did not return to its original mount identity"), err)
	}
	if err := os.Remove(f.target); err != nil {
		return err
	}
	return os.Remove(f.workspace)
}

func exerciseQualifiedLifecycle(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.close()) }()
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrUnavailable) {
		return errors.New("lease issued before trusted qualification")
	}
	if err := f.owner.Qualify(f.qualification); err != nil || f.owner.State() != StateQualified {
		return errors.Join(errors.New("trusted fixture did not qualify"), err)
	}
	if err := f.owner.Mount(contextBackground()); err != nil || f.owner.State() != StateMounted {
		return errors.Join(errors.New("qualified fixture did not mount"), err)
	}
	lease, err := f.owner.Acquire(contextBackground())
	if err != nil {
		return err
	}
	file, err := lease.OpenDirectory(".")
	if err != nil {
		lease.Close()
		return err
	}
	if _, err := file.Read(make([]byte, 1)); err == nil {
		return errors.New("metadata-only lease returned a content-readable descriptor")
	}
	if err := f.owner.Drain(); !errors.Is(err, ErrBusy) {
		return errors.New("drain did not report its active lease")
	}
	if _, err := f.owner.Acquire(contextBackground()); err == nil {
		return errors.New("draining owner issued a new lease")
	}
	if err := f.owner.Unmount(contextBackground()); !errors.Is(err, ErrBusy) || f.driver.unmountCalls != 0 {
		return errors.New("owner unmounted while a lease remained")
	}
	if err := lease.Close(); err != nil {
		return err
	}
	if _, err := file.Stat(); err == nil {
		return errors.New("lease release did not close the owner-issued descriptor")
	}
	err = f.owner.Unmount(contextBackground())
	if err != nil || f.owner.State() != StateUnavailable || f.driver.unmountCalls != 1 {
		after, observeErr := (linuxObserver{}).ObserveTarget(f.target)
		empty, emptyErr := (linuxObserver{}).TargetEmpty(f.target)
		return fmt.Errorf("verified unmount did not complete exactly once: state=%s calls=%d error=%v target_before=%+v target_after=%+v observe_error=%v empty=%t empty_error=%v",
			f.owner.State(), f.driver.unmountCalls, err, f.targetBefore, after, observeErr, empty, emptyErr)
	}
	return nil
}

func exerciseChangedIdentityRevocation(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.close()) }()
	if err := f.owner.Qualify(f.qualification); err != nil || f.owner.Mount(contextBackground()) != nil {
		return errors.Join(errors.New("identity-change fixture mount failed"), err)
	}
	lease, err := f.owner.Acquire(contextBackground())
	if err != nil {
		return err
	}
	file, err := lease.OpenDirectory(".")
	if err != nil {
		lease.Close()
		return err
	}
	if err := unix.Mount(source, f.target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired {
		return errors.New("changed mount identity was not quarantined")
	}
	if _, err := file.Stat(); err == nil {
		return errors.New("quarantine did not revoke an Owner-held descriptor")
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("quarantined Owner issued another lease")
	}
	if err := f.owner.Unmount(contextBackground()); !errors.Is(err, ErrReview) || f.driver.unmountCalls != 0 {
		return errors.New("quarantined Owner retried or performed cleanup")
	}
	return nil
}

func exerciseAmbiguousMountResult(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.close()) }()
	f.driver.loseMountResult = true
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	if err := f.owner.Mount(contextBackground()); !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired {
		return errors.New("lost completed mount result was not quarantined")
	}
	if err := f.owner.Mount(contextBackground()); !errors.Is(err, ErrReview) || f.driver.mountCalls != 1 {
		return errors.New("ambiguous mount was retried")
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("ambiguous mount received a lease")
	}
	return nil
}

func exerciseAmbiguousUnmountResult(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.close()) }()
	if err := f.owner.Qualify(f.qualification); err != nil || f.owner.Mount(contextBackground()) != nil {
		return errors.Join(errors.New("ambiguous-unmount fixture mount failed"), err)
	}
	if err := f.owner.Drain(); err != nil {
		return err
	}
	f.driver.loseUnmountResult = true
	if err := f.owner.Unmount(contextBackground()); !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired {
		return errors.New("lost completed unmount result was not quarantined")
	}
	if err := f.owner.Unmount(contextBackground()); !errors.Is(err, ErrReview) || f.driver.unmountCalls != 1 {
		return errors.New("ambiguous unmount was retried")
	}
	return nil
}

func exerciseMismatchedMountRefusal(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.close()) }()
	f.driver.bindSourceOverride = "/run"
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	if err := f.owner.Mount(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("mismatched mounted filesystem was accepted")
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) || f.driver.mountCalls != 1 {
		return errors.New("mismatched filesystem received a lease or was retried")
	}
	return nil
}

// Kept behind this QEMU-only file so the lifecycle API has no dependency on a
// product context or global cancellation source.
func contextBackground() context.Context { return context.Background() }

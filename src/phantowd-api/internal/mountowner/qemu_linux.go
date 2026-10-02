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
	qemuFixtureSource      = "/srv/phantowd/volumes/qemu-only"
	qemuFixtureUUID        = "11111111-2222-3333-4444-555555555555"
	qemuPlannerVolumeID    = "qemu-plan"
	qemuPlannerMountAnchor = "/srv/phantowd/volumes/qemu-plan"
	qemuMDStackMountAnchor = "/srv/phantowd/volumes/qemu-md-stack"
	qemuMDStackFilesystem  = "66666666-7777-8888-9999-aaaaaaaaaaaa"
)

const (
	QEMUMDStackFixtureSource   = "/run/phantowd-md-stack"
	QEMUMDStackFixtureVolumeID = "qemu-md-stack"
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
	if err := exerciseTargetReplacementRace(source); err != nil {
		return fmt.Errorf("mount target replacement race: %w", err)
	}
	if err := exerciseLateTargetReplacementRace(source); err != nil {
		return fmt.Errorf("late mount target replacement race: %w", err)
	}
	if err := exerciseSourceReplacementRace(source); err != nil {
		return fmt.Errorf("mount source replacement race: %w", err)
	}
	fmt.Println("PHANTOWD_MOUNT_OWNER_READY qualified_before_lease=true identity_change_blocks_new_access=true owner_handles_revoked=true set_lease_identity_loss=true returned_anchor_no_reuse=true ambiguous_mount_no_retry=true ambiguous_unmount_no_retry=true mismatch_no_lease=true target_fd_anchored=true target_replacement_not_used=true late_target_race_pinned_object_only=true late_target_race_quarantined=true source_fd_anchored=true source_replacement_quarantined=true scope=disposable-qemu-only")
	return nil
}

// WithQEMUMountedEvidence keeps a fixed-identity QEMU bind mount alive while a
// caller builds a candidate from its actual kernel mount tuple. It is compiled
// only into the disposable Linux/ARM QEMU guest and refuses every other path.
func WithQEMUMountedEvidence(source string, inspect func(MountedVolumeEvidence) error) (result error) {
	if inspect == nil {
		return errors.New("file-service mount integration requires an observer")
	}
	return withQEMUMountedOwner(source, func(owner *Owner) error {
		evidence, err := owner.ObserveMountedVolume()
		if err != nil || evidence.VolumeID() != qemuPlannerVolumeID || evidence.FilesystemUUID() != qemuFixtureUUID ||
			evidence.Compatibility() != qualifiedCompatibility || evidence.Generation() == 0 ||
			evidence.MountID() == 0 || evidence.DeviceMajor() == 0 {
			return errors.New("QEMU mount owner returned incomplete mounted evidence")
		}
		return inspect(evidence)
	})
}

// WithQEMUMountedSet exposes the fixed disposable QEMU roster to one internal
// integration callback. The roster constructor and mount remain private to
// this QEMU-only path; this does not establish production inventory or
// compatibility policy.
func WithQEMUMountedSet(source string, inspect func(*MountedVolumeSet) error) error {
	if inspect == nil {
		return errors.New("file-service mount-set integration requires an observer")
	}
	return withQEMUMountedOwner(source, func(owner *Owner) error {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return errors.New("QEMU mount-owner roster could not be created")
		}
		return inspect(set)
	})
}

// WithQEMUMountedSetEvidence runs a snapshot observer under all roster locks
// using the one fixed logical volume in the disposable guest.
func WithQEMUMountedSetEvidence(source string, inspect func(MountedVolumeSetEvidence) error) error {
	if inspect == nil {
		return errors.New("file-service mount-set integration requires an observer")
	}
	return WithQEMUMountedSet(source, func(set *MountedVolumeSet) error {
		evidence, err := set.Observe()
		if err != nil || !evidence.Complete() || evidence.Generation() == 0 || len(evidence.Volumes()) != 1 {
			return errors.New("QEMU mount-owner set returned incomplete evidence")
		}
		return inspect(evidence)
	})
}

// WithQEMUMDStackSetEvidence connects the separately verified M3.3 disposable
// MD/filesystem fixture to the M3.4 mount Owner. Its source, UUID, logical ID
// and destination are fixed; only the QEMU caller may invoke it, and the
// callback receives evidence while the one-member set and Owner are locked.
// It never opens a block device, assembles an array, or accesses user media.
func WithQEMUMDStackSetEvidence(source string, inspect func(MountedVolumeSetEvidence) error) error {
	if source != QEMUMDStackFixtureSource || inspect == nil {
		return errors.New("M3.3/M3.4 bridge requires its fixed disposable MD source")
	}
	return withQEMUMountedOwnerAt(source, qemuMDStackMountAnchor, QEMUMDStackFixtureVolumeID,
		qemuMDStackFilesystem, false, func(owner *Owner) error {
			set, err := newMountedVolumeSet([]string{QEMUMDStackFixtureVolumeID}, []*Owner{owner})
			if err != nil {
				return errors.New("QEMU MD mounted-volume roster could not be created")
			}
			return set.WithEvidence(inspect)
		})
}

// RunQEMUMultiVolumeLeaseLossFixture composes two distinct disposable
// filesystems into a fixed roster: the synthetic writable ext2 fixture and a
// read-only synthetic MD filesystem. It is available only to QEMU-tagged
// integration code; it is not a production roster or recovery path.
func RunQEMUMultiVolumeLeaseLossFixture() error {
	var innerReviewObserved bool
	err := withQEMUMountedOwner(qemuFixtureSource, func(healthy *Owner) error {
		innerErr := withQEMUMountedOwnerAt(QEMUMDStackFixtureSource, qemuMDStackMountAnchor,
			QEMUMDStackFixtureVolumeID, qemuMDStackFilesystem, false,
			func(lost *Owner) error {
				return exerciseQEMUMultiVolumeLeaseLoss(healthy, lost)
			})
		if !errors.Is(innerErr, ErrReview) {
			return errors.Join(errors.New("lost-volume fixture did not preserve review quarantine during exact teardown"), innerErr)
		}
		innerReviewObserved = true
		if healthy.State() != StateMounted {
			return errors.New("lost MD volume quarantined the independent healthy Owner")
		}
		lease, err := healthy.Acquire(contextBackground())
		if err != nil {
			return fmt.Errorf("healthy Owner could not issue a fresh independent lease: %w", err)
		}
		file, err := lease.OpenDirectory(".")
		if err != nil {
			_ = lease.Close()
			return fmt.Errorf("fresh healthy Owner lease could not open its root: %w", err)
		}
		if err := lease.Close(); err != nil {
			return fmt.Errorf("fresh healthy Owner lease did not release: %w", err)
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.New("fresh healthy Owner lease did not revoke its tracked descriptor")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !innerReviewObserved {
		return errors.New("two-volume fixture did not observe quarantined teardown")
	}
	fmt.Println("PHANTOWD_M35_TWO_VOLUME_READY distinct_filesystems=true lost_volume_quarantined=true lost_handles_revoked=true healthy_group_lease_survived=true fresh_healthy_owner_lease=true roster_reacquire=all_or_error scope=disposable-qemu-only")
	return nil
}

func withQEMUMountedOwner(source string, inspect func(*Owner) error) (result error) {
	return withQEMUMountedOwnerAt(source, qemuPlannerMountAnchor, qemuPlannerVolumeID,
		qemuFixtureUUID, true, inspect)
}

func withQEMUMountedOwnerAt(source, target, volumeID, filesystemUUID string, requireWritable bool, inspect func(*Owner) error) (result error) {
	fixedSource := source == qemuFixtureSource && target == qemuPlannerMountAnchor &&
		volumeID == qemuPlannerVolumeID && filesystemUUID == qemuFixtureUUID && requireWritable
	fixedMDSource := source == QEMUMDStackFixtureSource && target == qemuMDStackMountAnchor &&
		volumeID == QEMUMDStackFixtureVolumeID && filesystemUUID == qemuMDStackFilesystem && !requireWritable
	if (!fixedSource && !fixedMDSource) || inspect == nil || runtime.GOOS != "linux" || runtime.GOARCH != "arm" {
		return errors.New("file-service mount integration requires its fixed QEMU source")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("file-service mount integration requires the disposable Versatile PB guest")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed QEMU planner mount anchor already exists")
	}
	if err := os.Mkdir(target, 0700); err != nil {
		return errors.New("fixed QEMU planner mount anchor could not be created")
	}
	f, err := newQEMUMountFixtureAtExpected(source, target, volumeID, "", filesystemUUID, requireWritable)
	if err != nil {
		_ = os.Remove(target)
		return err
	}
	mounted := false
	defer func() {
		if mounted && f.owner.State() == StateMounted {
			if drainErr := f.owner.Drain(); drainErr == nil {
				if unmountErr := f.owner.Unmount(context.Background()); unmountErr != nil {
					result = errors.Join(result, unmountErr)
				} else {
					mounted = false
				}
			} else {
				result = errors.Join(result, drainErr)
			}
		}
		result = errors.Join(result, f.close())
	}()
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	if err := f.owner.Mount(context.Background()); err != nil {
		return err
	}
	mounted = true
	if err := f.owner.Verify(); err != nil {
		return err
	}
	inspectErr := inspect(f.owner)
	verifyErr := f.owner.Verify()
	drainErr := f.owner.Drain()
	var unmountErr error
	if drainErr == nil {
		unmountErr = f.owner.Unmount(context.Background())
		if unmountErr == nil {
			mounted = false
		}
	}
	return errors.Join(inspectErr, verifyErr, drainErr, unmountErr)
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
	return observeTargetFD(fd)
}

func observeTargetFD(fd int) (TargetIdentity, error) {
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

func (linuxObserver) PinTarget(path string) (targetHandle, error) {
	fd, err := openPath(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	pin := &linuxTargetPin{file: os.NewFile(uintptr(fd), "mount-owner-target-pin")}
	if _, err := pin.Identity(); err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

type linuxTargetPin struct{ file *os.File }

func (p *linuxTargetPin) Identity() (TargetIdentity, error) {
	if p == nil || p.file == nil {
		return TargetIdentity{}, mountguard.ErrUnavailable
	}
	return observeTargetFD(int(p.file.Fd()))
}

func (p *linuxTargetPin) Empty() (bool, error) {
	if p == nil || p.file == nil {
		return false, mountguard.ErrUnavailable
	}
	fd, err := unix.Openat(int(p.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, mountguard.ErrUnavailable
	}
	directory := os.NewFile(uintptr(fd), "mount-owner-target-empty-check")
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

func (p *linuxTargetPin) File() *os.File {
	if p == nil {
		return nil
	}
	return p.file
}

func (p *linuxTargetPin) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
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
	target             string
	bindSourceOverride string
	beforeMount        func() error
	beforeAttach       func() error
	loseMountResult    bool
	loseUnmountResult  bool
	mountCalls         int
	unmountCalls       int
	mountAttached      bool
}

func (d *qemuBindDriver) MountBind(source, target *os.File) error {
	d.mountCalls++
	if source == nil || target == nil {
		return ErrInvalid
	}
	if d.beforeMount != nil {
		if err := d.beforeMount(); err != nil {
			return err
		}
	}
	pinnedTarget, err := observeTargetFD(int(target.Fd()))
	pathTarget, pathErr := (linuxObserver{}).ObserveTarget(d.target)
	if pathErr != nil || pinnedTarget != pathTarget {
		return errors.Join(mountguard.ErrMismatch, pathErr)
	}
	sourceFD := int(source.Fd())
	var overrideFD int
	if d.bindSourceOverride != "" {
		overrideFD, err = openPath(d.bindSourceOverride, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
		if err != nil {
			return err
		}
		defer unix.Close(overrideFD)
		sourceFD = overrideFD
	}
	mountFD, err := unix.OpenTree(sourceFD, "", uint(unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
	if err != nil {
		return err
	}
	defer unix.Close(mountFD)
	if d.beforeAttach != nil {
		if err := d.beforeAttach(); err != nil {
			return err
		}
	}
	if err := unix.MoveMount(mountFD, "", int(target.Fd()), "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return err
	}
	d.mountAttached = true
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
	return newQEMUMountFixtureAt(source, target, "qemu-only", workspace)
}

func newQEMUMountFixtureAt(source, target, volumeID, workspace string) (*qemuMountFixture, error) {
	return newQEMUMountFixtureAtExpected(source, target, volumeID, workspace, qemuFixtureUUID, true)
}

func newQEMUMountFixtureAtExpected(source, target, volumeID, workspace, filesystemUUID string, requireWritable bool) (*qemuMountFixture, error) {
	observer := linuxObserver{}
	sourceExpected, err := observer.ObserveMount(source)
	if err != nil || sourceExpected.FilesystemType != uint32(unix.EXT4_SUPER_MAGIC) || sourceExpected.RequireWritable != requireWritable {
		os.Remove(target)
		os.Remove(workspace)
		return nil, mountguard.ErrMismatch
	}
	sourceExpected.FilesystemUUID = filesystemUUID
	sourceRoot, err := mountguard.Open(source, sourceExpected)
	if err != nil {
		os.Remove(target)
		os.Remove(workspace)
		return nil, err
	}
	qualification := &Qualification{volumeID: volumeID, compatibility: qualifiedCompatibility,
		source: source, expected: sourceExpected, sourceRoot: sourceRoot}
	driver := &qemuBindDriver{target: target}
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
	if f.workspace == "" {
		return nil
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

func exerciseChangedIdentityRevocation(source string) error {
	callbackCompleted := false
	result := withQEMUMountedOwner(source, func(owner *Owner) error {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return errors.New("identity-change fixture could not create its fixed volume roster")
		}
		lease, evidence, err := set.Acquire(contextBackground())
		if err != nil {
			return err
		}
		if !evidence.Complete() || len(evidence.Volumes()) != 1 {
			return errors.New("identity-change fixture received incomplete volume-set evidence")
		}
		file, err := lease.OpenDirectory(qemuPlannerVolumeID, ".")
		if err != nil {
			_ = lease.Close()
			return err
		}
		if err := unix.Mount(source, owner.target, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if _, err := lease.OpenDirectory(qemuPlannerVolumeID, "."); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
			return errors.New("changed mount identity was not quarantined")
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.New("group lease quarantine did not revoke its tracked descriptor")
		}
		if err := unix.Unmount(owner.target, 0); err != nil {
			return errors.New("identity-change fixture could not remove its exact overmount")
		}
		if _, err := lease.OpenDirectory(qemuPlannerVolumeID, "."); !errors.Is(err, ErrReview) {
			return errors.New("returned mount anchor revived the quarantined group lease")
		}
		if _, evidence, err := set.Acquire(contextBackground()); !errors.Is(err, ErrReview) || evidence.Complete() {
			return errors.New("returned mount anchor revived the quarantined Owner roster")
		}
		if err := lease.Close(); err != nil {
			return errors.New("quarantined group lease did not release cleanly")
		}
		if err := owner.Unmount(contextBackground()); !errors.Is(err, ErrReview) {
			return errors.New("quarantined Owner retried or performed cleanup")
		}
		callbackCompleted = true
		return nil
	})
	if !callbackCompleted || !errors.Is(result, ErrReview) {
		return errors.Join(errors.New("group-lease identity-loss fixture did not complete quarantine"), result)
	}
	if _, err := os.Lstat(qemuPlannerMountAnchor); !errors.Is(err, os.ErrNotExist) {
		return errors.New("identity-loss fixture did not remove its exact QEMU mount anchor")
	}
	return nil
}

func exerciseQEMUMultiVolumeLeaseLoss(healthy, lost *Owner) error {
	set, err := newMountedVolumeSet(
		[]string{qemuPlannerVolumeID, QEMUMDStackFixtureVolumeID},
		[]*Owner{healthy, lost},
	)
	if err != nil {
		return errors.New("two-volume fixture could not construct its fixed roster")
	}
	lease, evidence, err := set.Acquire(contextBackground())
	if err != nil {
		return fmt.Errorf("two-volume fixture could not acquire the complete roster: %w", err)
	}
	if !evidence.Complete() || len(evidence.Volumes()) != 2 {
		_ = lease.Close()
		return errors.New("two-volume fixture acquired incomplete roster evidence")
	}
	healthyHandle, err := lease.OpenDirectory(qemuPlannerVolumeID, ".")
	if err != nil {
		_ = lease.Close()
		return fmt.Errorf("healthy member was not usable before loss: %w", err)
	}
	lostHandle, err := lease.OpenDirectory(QEMUMDStackFixtureVolumeID, ".")
	if err != nil {
		_ = lease.Close()
		return fmt.Errorf("MD member was not usable before loss: %w", err)
	}
	if err := unix.Mount(qemuFixtureSource, lost.target, "", unix.MS_BIND, ""); err != nil {
		_ = lease.Close()
		return fmt.Errorf("could not create the exact disposable MD-target overmount: %w", err)
	}
	if _, err := lease.OpenDirectory(QEMUMDStackFixtureVolumeID, "."); !errors.Is(err, ErrReview) || lost.State() != StateReviewRequired {
		return errors.New("changed MD mount identity was not quarantined")
	}
	if _, err := lostHandle.Stat(); !errors.Is(err, os.ErrClosed) {
		return errors.New("changed MD volume did not revoke its tracked descriptor")
	}
	if _, err := healthyHandle.Stat(); err != nil {
		return fmt.Errorf("MD loss revoked an unrelated healthy-volume descriptor: %w", err)
	}
	if _, err := lease.OpenDirectory(qemuPlannerVolumeID, "."); err != nil {
		return fmt.Errorf("MD loss blocked an existing lease from the healthy volume: %w", err)
	}
	if err := unix.Unmount(lost.target, 0); err != nil {
		return fmt.Errorf("could not remove the exact disposable MD-target overmount: %w", err)
	}
	if _, err := lease.OpenDirectory(QEMUMDStackFixtureVolumeID, "."); !errors.Is(err, ErrReview) {
		return errors.New("return of the old MD anchor revived its quarantined lease")
	}
	if _, evidence, err := set.Acquire(contextBackground()); !errors.Is(err, ErrReview) || evidence.Complete() {
		return errors.New("return of one anchor restored complete-roster lease authority")
	}
	if err := lease.Close(); err != nil {
		return fmt.Errorf("two-volume lease did not close after member quarantine: %w", err)
	}
	if err := lost.Unmount(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("quarantined MD Owner retried or performed implicit unmount")
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
	if err := f.owner.Mount(contextBackground()); !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired || !f.driver.mountAttached {
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

func exerciseTargetReplacementRace(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	pinnedPath := f.target + "-pinned"
	var moved, replacementCreated bool
	var replacementIdentity TargetIdentity
	var injectionErr error
	f.driver.beforeMount = func() error {
		if injectionErr = os.Rename(f.target, pinnedPath); injectionErr != nil {
			return injectionErr
		}
		moved = true
		if injectionErr = os.Mkdir(f.target, 0700); injectionErr != nil {
			return injectionErr
		}
		replacementCreated = true
		replacementIdentity, injectionErr = (linuxObserver{}).ObserveTarget(f.target)
		return injectionErr
	}
	defer func() {
		result = errors.Join(result, f.owner.Close())
		observer := linuxObserver{}
		for _, path := range []string{f.target, pinnedPath} {
			current, observeErr := observer.ObserveTarget(path)
			if observeErr == nil && current.MountRoot {
				if unmountErr := unix.Unmount(path, 0); unmountErr != nil {
					result = errors.Join(result, fmt.Errorf("fixture unmount %s: %w", path, unmountErr))
				}
			}
		}
		if replacementCreated {
			if removeErr := os.Remove(f.target); removeErr != nil {
				result = errors.Join(result, removeErr)
			}
		}
		if moved {
			if renameErr := os.Rename(pinnedPath, f.target); renameErr != nil {
				result = errors.Join(result, renameErr)
			}
		}
		result = errors.Join(result, f.close())
	}()
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	err = f.owner.Mount(contextBackground())
	if injectionErr != nil {
		return fmt.Errorf("could not inject target replacement: %w", injectionErr)
	}
	if !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired || f.driver.mountCalls != 1 {
		return fmt.Errorf("replacement target was mounted or outcome was not quarantined: state=%s calls=%d err=%v", f.owner.State(), f.driver.mountCalls, err)
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("target substitution received a lease")
	}
	current, err := (linuxObserver{}).ObserveTarget(f.target)
	if err != nil || current != replacementIdentity {
		return errors.Join(errors.New("mount used the substituted target path"), err)
	}
	original, err := (linuxObserver{}).ObserveTarget(pinnedPath)
	if err != nil || original.MountRoot {
		return errors.Join(errors.New("target path race attached a mount before the pinned-target check"), err)
	}
	return nil
}

func exerciseLateTargetReplacementRace(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	pinnedPath := f.target + "-late-pinned"
	var moved, replacementCreated bool
	var replacementIdentity TargetIdentity
	var injectionErr error
	f.driver.beforeAttach = func() error {
		if injectionErr = os.Rename(f.target, pinnedPath); injectionErr != nil {
			return injectionErr
		}
		moved = true
		if injectionErr = os.Mkdir(f.target, 0700); injectionErr != nil {
			return injectionErr
		}
		replacementCreated = true
		replacementIdentity, injectionErr = (linuxObserver{}).ObserveTarget(f.target)
		return injectionErr
	}
	defer func() {
		result = errors.Join(result, f.owner.Close())
		observer := linuxObserver{}
		for _, path := range []string{f.target, pinnedPath} {
			current, observeErr := observer.ObserveTarget(path)
			if observeErr == nil && current.MountRoot {
				if unmountErr := unix.Unmount(path, 0); unmountErr != nil {
					result = errors.Join(result, fmt.Errorf("fixture unmount %s: %w", path, unmountErr))
				}
			}
		}
		if replacementCreated {
			if removeErr := os.Remove(f.target); removeErr != nil {
				result = errors.Join(result, removeErr)
			}
		}
		if moved {
			if renameErr := os.Rename(pinnedPath, f.target); renameErr != nil {
				result = errors.Join(result, renameErr)
			}
		}
		result = errors.Join(result, f.close())
	}()
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	err = f.owner.Mount(contextBackground())
	if injectionErr != nil {
		return fmt.Errorf("could not inject late target replacement: %w", injectionErr)
	}
	if !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired || f.driver.mountCalls != 1 || !f.driver.mountAttached {
		return fmt.Errorf("late target replacement was accepted or not quarantined: state=%s calls=%d attached=%t err=%v",
			f.owner.State(), f.driver.mountCalls, f.driver.mountAttached, err)
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("late target replacement received a lease")
	}
	replacement, err := (linuxObserver{}).ObserveTarget(f.target)
	if err != nil || replacement != replacementIdentity || replacement.MountRoot {
		return errors.Join(errors.New("late target replacement was used as the mount destination"), err)
	}
	pinned, err := (linuxObserver{}).ObserveMount(pinnedPath)
	if err != nil || !sameMountedFilesystem(pinned, f.qualification.expected) {
		return errors.Join(errors.New("late target race did not attach only to the pinned object"), err)
	}
	return nil
}

func exerciseSourceReplacementRace(source string) (result error) {
	f, err := newQEMUMountFixture(source)
	if err != nil {
		return err
	}
	var overmounted bool
	var injectionErr error
	f.driver.beforeMount = func() error {
		injectionErr = unix.Mount("/run", source, "", unix.MS_BIND, "")
		overmounted = injectionErr == nil
		return injectionErr
	}
	defer func() {
		result = errors.Join(result, f.close())
		if overmounted {
			result = errors.Join(result, unix.Unmount(source, 0))
		}
	}()
	if err := f.owner.Qualify(f.qualification); err != nil {
		return err
	}
	err = f.owner.Mount(contextBackground())
	if injectionErr != nil {
		return fmt.Errorf("could not inject source replacement: %w", injectionErr)
	}
	if !errors.Is(err, ErrReview) || f.owner.State() != StateReviewRequired || f.driver.mountCalls != 1 {
		return fmt.Errorf("source replacement was accepted or not quarantined: state=%s calls=%d err=%v", f.owner.State(), f.driver.mountCalls, err)
	}
	if _, err := f.owner.Acquire(contextBackground()); !errors.Is(err, ErrReview) {
		return errors.New("source substitution received a lease")
	}
	mounted, err := (linuxObserver{}).ObserveMount(f.target)
	if err != nil || !sameMountedFilesystem(mounted, f.qualification.expected) {
		return errors.Join(errors.New("bind source was not the pinned qualified filesystem"), err)
	}
	return nil
}

// Kept behind this QEMU-only file so the lifecycle API has no dependency on a
// product context or global cancellation source.
func contextBackground() context.Context { return context.Background() }

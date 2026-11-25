// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// LinuxVolumeGrant is supplied by the trusted storage supervisor after it has
// admitted the physical or managed volume and mounted it in this namespace.
// Source is a borrowed descriptor for that mounted root. Expected includes
// the independently authorized filesystem UUID and the supervisor's kernel
// observation of the mount it owns. The supervisor must serialize changes to
// these mounts and their target hierarchy with this package.
type LinuxVolumeGrant struct {
	VolumeID   string
	SourcePath string
	Source     *os.File
	Expected   mountguard.Expected
}

// LinuxMountedRoster owns the bind mounts supplied to the service owners.
// The producing supervisor holds it until all dependent leases are closed.
type LinuxMountedRoster struct {
	set *MountedVolumeSet
}

// Serialize publishing and retiring fixed-path rosters in this process.
var linuxRosterMu sync.Mutex

// AdmitLinuxMountedRoster binds a complete, independently approved grant
// roster to pre-existing, protected service anchors. It opens only mounted
// directories, and publishes nothing until every bind has been verified.
func AdmitLinuxMountedRoster(ctx context.Context, grants []LinuxVolumeGrant) (*LinuxMountedRoster, error) {
	if ctx == nil || len(grants) == 0 || len(grants) > shareconfig.MaxVolumes {
		return nil, ErrInvalid
	}
	linuxRosterMu.Lock()
	defer linuxRosterMu.Unlock()
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	ordered := slices.Clone(grants)
	slices.SortFunc(ordered, func(a, b LinuxVolumeGrant) int { return strings.Compare(a.VolumeID, b.VolumeID) })
	if err := validateLinuxGrants(ordered); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(ordered))
	owners := make([]*Owner, 0, len(ordered))
	fail := func(cause error) (*LinuxMountedRoster, error) {
		if !errors.Is(cause, ErrReview) {
			releaseErr := releaseLinuxOwners(context.WithoutCancel(ctx), owners)
			if releaseErr == nil {
				return nil, cause
			}
			cause = errors.Join(cause, releaseErr)
		}
		return nil, &linuxRosterReview{owners: owners, cause: cause}
	}
	for _, grant := range ordered {
		target := filepath.Join(shareconfig.VolumeMountRoot, grant.VolumeID)
		if err := validateLinuxTarget(target); err != nil {
			return fail(fmt.Errorf("validate volume %q target: %w", grant.VolumeID, err))
		}
		owner, err := prepareLinuxOwner(grant, target)
		if err != nil {
			return fail(fmt.Errorf("qualify volume %q: %w", grant.VolumeID, err))
		}
		ids = append(ids, grant.VolumeID)
		owners = append(owners, owner)
	}
	set, err := newMountedVolumeSet(ids, owners)
	if err != nil {
		return fail(err)
	}
	for index, owner := range owners {
		if err := owner.Mount(ctx); err != nil {
			return fail(fmt.Errorf("bind volume %q: %w", ids[index], err))
		}
	}
	if _, err := set.Observe(); err != nil {
		return fail(err)
	}
	return &LinuxMountedRoster{set: set}, nil
}

func validateLinuxGrants(grants []LinuxVolumeGrant) error {
	ids := make(map[string]bool, len(grants))
	mounts := make(map[uint64]bool, len(grants))
	devices := make(map[[2]uint32]bool, len(grants))
	uuids := make(map[string]bool, len(grants))
	for _, grant := range grants {
		expected := grant.Expected
		device := [2]uint32{expected.DeviceMajor, expected.DeviceMinor}
		if !validVolumeID(grant.VolumeID) || !validAbsolute(grant.SourcePath) || grant.Source == nil ||
			!validExpected(expected) || expected.FilesystemType != unix.EXT4_SUPER_MAGIC ||
			ids[grant.VolumeID] || mounts[expected.MountID] || devices[device] || uuids[expected.FilesystemUUID] {
			return ErrInvalid
		}
		for _, other := range grants {
			if sameOrNestedPath(grant.SourcePath, filepath.Join(shareconfig.VolumeMountRoot, other.VolumeID)) {
				return ErrInvalid
			}
		}
		ids[grant.VolumeID] = true
		mounts[expected.MountID] = true
		devices[device] = true
		uuids[expected.FilesystemUUID] = true
	}
	return nil
}

func prepareLinuxOwner(grant LinuxVolumeGrant, target string) (*Owner, error) {
	connection, err := grant.Source.SyscallConn()
	if err != nil {
		return nil, ErrRejected
	}
	var identity TargetIdentity
	var observeErr error
	if err := connection.Control(func(fd uintptr) {
		identity, observeErr = observeTargetFD(int(fd))
	}); err != nil || observeErr != nil {
		return nil, ErrRejected
	}
	expected := grant.Expected
	if !identity.MountRoot || identity.MountID != expected.MountID || identity.RootInode != expected.RootInode ||
		identity.DeviceMajor != expected.DeviceMajor || identity.DeviceMinor != expected.DeviceMinor ||
		identity.FilesystemType != expected.FilesystemType {
		return nil, ErrRejected
	}
	openRoot := func(path string, expected mountguard.Expected) (rootGuard, error) {
		return mountguard.Open(path, expected)
	}
	owner, err := newOwner(target, linuxBindDriver{target: target}, linuxObserver{}, openRoot)
	if err != nil {
		return nil, err
	}
	root, err := openRoot(grant.SourcePath, expected)
	if err != nil {
		return nil, errors.Join(ErrRejected, err)
	}
	err = owner.Qualify(&Qualification{volumeID: grant.VolumeID, compatibility: qualifiedCompatibility,
		source: grant.SourcePath, expected: expected, sourceRoot: root})
	if err != nil {
		return nil, err
	}
	return owner, nil
}

func validateLinuxTarget(target string) error {
	for dir := target; dir != "/"; dir = filepath.Dir(dir) {
		var stat unix.Stat_t
		if err := unix.Lstat(dir, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0022 != 0 || stat.Uid != 0 {
			return ErrRejected
		}
	}
	fd, err := openPath(target, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return requireLocalMountParent(fd)
}

// Volumes returns the service-lease entry point for this roster.
func (r *LinuxMountedRoster) Volumes() *MountedVolumeSet {
	if r == nil {
		return nil
	}
	return r.set
}

// Close retires the roster in one admission step before unmounting its binds
// in reverse order. Outstanding leases leave the entire roster usable. After
// retirement, uncertain teardown is sticky and requires operator review.
func (r *LinuxMountedRoster) Close(ctx context.Context) error {
	if r == nil || r.set == nil || ctx == nil {
		return ErrInvalid
	}
	linuxRosterMu.Lock()
	defer linuxRosterMu.Unlock()
	if r.set.retired {
		return r.set.retireErr
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := r.retire(); err != nil {
		return err
	}
	if err := releaseLinuxOwners(ctx, r.set.lockOrder); err != nil {
		r.set.retireErr = &linuxRosterReview{owners: r.set.lockOrder, cause: err}
	}
	return r.set.retireErr
}

func (r *LinuxMountedRoster) retire() error {
	set := r.set
	set.mu.Lock()
	defer set.mu.Unlock()
	for _, owner := range set.lockOrder {
		owner.mu.Lock()
	}
	defer func() {
		for index := len(set.lockOrder) - 1; index >= 0; index-- {
			set.lockOrder[index].mu.Unlock()
		}
	}()
	for _, owner := range set.lockOrder {
		if len(owner.leases) != 0 {
			return ErrBusy
		}
	}
	set.retired = true
	return nil
}

func releaseLinuxOwners(ctx context.Context, owners []*Owner) error {
	for index := len(owners) - 1; index >= 0; index-- {
		owner := owners[index]
		switch owner.State() {
		case StateMounted:
			if err := owner.Drain(); err != nil {
				return err
			}
			if err := owner.Unmount(ctx); err != nil {
				return err
			}
		case StateReviewRequired, StateMounting, StateDraining:
			return ErrReview
		}
		if err := owner.Close(); err != nil {
			return err
		}
	}
	return nil
}

type linuxRosterReview struct {
	constructionreview.Marker
	owners []*Owner
	cause  error
}

func (r *linuxRosterReview) Error() string   { return r.cause.Error() }
func (r *linuxRosterReview) Unwrap() []error { return []error{ErrReview, r.cause} }

type linuxBindDriver struct{ target string }

func (d linuxBindDriver) MountBind(source, target *os.File) (result error) {
	pinned, err := observeTargetFD(int(target.Fd()))
	if err != nil {
		return err
	}
	if err := requireLocalMountParent(int(target.Fd())); err != nil {
		return err
	}
	tree, err := unix.OpenTree(int(source.Fd()), "", unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(tree)) }()
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOEXEC}
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, attr); err != nil {
		return err
	}
	named, err := (linuxObserver{}).ObserveTarget(d.target)
	if err != nil || named != pinned || named.MountRoot {
		return errors.Join(ErrRejected, err)
	}
	return unix.MoveMount(tree, "", int(target.Fd()), "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

func (d linuxBindDriver) Unmount(target string) error {
	if target != d.target {
		return ErrInvalid
	}
	return unix.Unmount(target, unix.UMOUNT_NOFOLLOW)
}

func requireLocalMountParent(fd int) error {
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat); err != nil {
		return err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return ErrRejected
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer mounts.Close()
	return localMountParent(bufio.NewScanner(mounts), strconv.FormatUint(stat.Mnt_id, 10))
}

func localMountParent(mounts *bufio.Scanner, id string) error {
	for mounts.Scan() {
		fields := strings.Fields(mounts.Text())
		if len(fields) == 0 || fields[0] != id {
			continue
		}
		if len(fields) < 10 {
			return ErrRejected
		}
		for _, field := range fields[6:] {
			switch {
			case field == "-":
				return nil
			case strings.HasPrefix(field, "shared:"), strings.HasPrefix(field, "master:"), strings.HasPrefix(field, "propagate_from:"):
				return ErrRejected
			}
		}
		return ErrRejected
	}
	return errors.Join(ErrRejected, mounts.Err())
}

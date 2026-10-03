//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

type mountedExtCensusCoverage struct {
	mountCount, observedRootCount, processRootExcluded, subtreeExcluded int
	unsupportedFilesystemExcluded, zeroMajorExcluded                    int
}

// This private observation is complete only for its declared namespace/scope.
// It is not a qualification, stable identity, global-use proof or mount lease.
type trustedMountedExtCensus struct {
	coverage   mountedExtCensusCoverage
	mounts     mountSnapshot
	storage    storageSnapshot
	arrays     []mdArrayStorageIdentity
	roots      mountguard.MountedInventory
	identities []mountedStorageIdentity
}

func (trustedMountedExtCensus) MarshalJSON() ([]byte, error) {
	return nil, errMountedStorageIdentityIncomplete
}

func (*trustedMountedExtCensus) UnmarshalJSON([]byte) error {
	return errMountedStorageIdentityIncomplete
}

type mountedExtRootObserver func([]string) (mountguard.MountedInventory, error)

// Not wired to product startup or HTTP. Only the existing QEMU MD fixture
// calls this fixed reader; no arbitrary subset is supplied by its caller.
func collectTrustedMountedExtCensus(ctx context.Context, sysfs, proc fs.FS) (trustedMountedExtCensus, error) {
	return collectTrustedMountedExtCensusWith(ctx, sysfs, proc, mountguard.ObserveMounted)
}

// Recheck compares complete point-in-time observations, not a selected policy
// subset. It neither retains descriptors nor grants a lease/activation token.
// Success says nothing about changes after this call returns.
func recheckTrustedMountedExtCensus(ctx context.Context, previous trustedMountedExtCensus, sysfs, proc fs.FS) error {
	return recheckTrustedMountedExtCensusWith(ctx, previous, sysfs, proc, mountguard.ObserveMounted)
}

// The observer is a private in-process test seam, never supplied by HTTP.
// The caller owns previous and must not mutate it concurrently with this call.
func recheckTrustedMountedExtCensusWith(ctx context.Context, previous trustedMountedExtCensus, sysfs, proc fs.FS, observe mountedExtRootObserver) error {
	if ctx == nil || ctx.Err() != nil || sysfs == nil || proc == nil || observe == nil ||
		validateMountedExtCensus(previous) != nil {
		return errMountedStorageIdentityIncomplete
	}
	current, err := collectTrustedMountedExtCensusWith(ctx, sysfs, proc, observe)
	if err != nil || ctx.Err() != nil || validateMountedExtCensus(current) != nil ||
		previous.coverage != current.coverage || !sameMountSnapshot(previous.mounts, current.mounts) ||
		!sameStorageSnapshot(previous.storage, current.storage) || !sameMountedCensusArrays(previous.arrays, current.arrays) ||
		!sameMountedCensusRoots(previous.roots, current.roots) {
		return errMountedStorageIdentityIncomplete
	}
	return nil
}

// The observer argument is an in-process test seam, never request input.
func collectTrustedMountedExtCensusWith(ctx context.Context, sysfs, proc fs.FS, observe mountedExtRootObserver) (trustedMountedExtCensus, error) {
	fail := func() (trustedMountedExtCensus, error) {
		return trustedMountedExtCensus{}, errMountedStorageIdentityIncomplete
	}
	if ctx == nil || ctx.Err() != nil || sysfs == nil || proc == nil || observe == nil {
		return fail()
	}
	mounts, err := collectMountInventory(proc, time.Now())
	if err != nil {
		return fail()
	}
	storage, arrays, err := collectMDStorageIdentitySnapshot(sysfs, proc)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	anchors, coverage, err := planMountedExtCensus(storage, mounts)
	if err != nil {
		return fail()
	}
	roots := mountguard.MountedInventory{Mounts: []mountguard.MountedIdentity{}, ConflictingUUIDs: []string{}}
	identities := []mountedStorageIdentity{}
	if len(anchors) != 0 {
		roots, err = observe(append([]string{}, anchors...))
		if err != nil || ctx.Err() != nil || !mountedCensusRootsMatch(roots, anchors, mounts) {
			return fail()
		}
		// Own the first result before invoking an observer which may reuse buffers.
		roots.Mounts = append([]mountguard.MountedIdentity{}, roots.Mounts...)
		roots.ConflictingUUIDs = append([]string{}, roots.ConflictingUUIDs...)
		identities, err = correlateObservedMountedStorageIdentity(storage, arrays, roots)
		if err != nil || ctx.Err() != nil {
			return fail()
		}
		current, err := observe(append([]string{}, anchors...))
		if err != nil || ctx.Err() != nil || !sameMountedCensusRoots(roots, current) {
			return fail()
		}
	}
	currentStorage, currentArrays, err := collectMDStorageIdentitySnapshot(sysfs, proc)
	if err != nil || !sameStorageSnapshot(storage, currentStorage) || !sameMountedCensusArrays(arrays, currentArrays) {
		return fail()
	}
	currentMounts, err := collectMountInventory(proc, time.Now())
	if err != nil || !sameMountSnapshot(mounts, currentMounts) || ctx.Err() != nil {
		return fail()
	}
	return trustedMountedExtCensus{coverage: coverage, mounts: mounts, storage: storage, arrays: arrays, roots: roots, identities: identities}, nil
}

func planMountedExtCensus(storage storageSnapshot, mounts mountSnapshot) ([]string, mountedExtCensusCoverage, error) {
	if _, err := completeObservedBlockDeviceSet(storage); err != nil || !mounts.collectionComplete ||
		mounts.SchemaVersion != 1 || mounts.Scope != "current-process-mount-namespace" || !mounts.ReadOnly ||
		mounts.FilesystemContentsRead || mounts.MountOperationsPerformed || mounts.Mounts == nil ||
		len(mounts.Mounts) < 1 || len(mounts.Mounts) > maxMountEntries || mounts.MountCount != len(mounts.Mounts) {
		return nil, mountedExtCensusCoverage{}, errMountedStorageIdentityIncomplete
	}
	devices := make(map[observedDeviceNumber]bool, len(storage.Observations))
	for _, block := range storage.Observations {
		devices[observedDeviceNumber{major: block.Major, minor: block.Minor}] = true
	}
	coverage := mountedExtCensusCoverage{mountCount: len(mounts.Mounts)}
	anchors := []string{}
	seenPaths, seenIDs := make(map[string]bool), make(map[uint32]bool)
	for _, mount := range mounts.Mounts {
		if mount.mountInfoID == 0 || seenIDs[mount.mountInfoID] || seenPaths[mount.MountPoint] ||
			!canonicalMountedCensusPath(mount.MountPoint) || !canonicalMountedCensusPath(mount.filesystemRoot) ||
			!validMountFilesystem(mount.Filesystem) {
			return nil, mountedExtCensusCoverage{}, errMountedStorageIdentityIncomplete
		}
		seenIDs[mount.mountInfoID], seenPaths[mount.MountPoint] = true, true
		if mount.DeviceMajor == 0 {
			coverage.zeroMajorExcluded++
			continue
		}
		if !devices[observedDeviceNumber{major: mount.DeviceMajor, minor: mount.DeviceMinor}] {
			return nil, mountedExtCensusCoverage{}, errMountedStorageIdentityIncomplete
		}
		switch {
		case mount.MountPoint == "/":
			coverage.processRootExcluded++
		case mount.Filesystem != "ext2" && mount.Filesystem != "ext3" && mount.Filesystem != "ext4":
			coverage.unsupportedFilesystemExcluded++
		case mount.filesystemRoot != "/":
			coverage.subtreeExcluded++
		default:
			if len(anchors) == maxMountedFilesystemAnchors {
				return nil, mountedExtCensusCoverage{}, errMountedStorageIdentityIncomplete
			}
			anchors = append(anchors, mount.MountPoint)
		}
	}
	sort.Strings(anchors)
	coverage.observedRootCount = len(anchors)
	return anchors, coverage, nil
}

func canonicalMountedCensusPath(value string) bool {
	return len(value) > 0 && len(value) <= maxMountPathBytes && path.IsAbs(value) &&
		path.Clean(value) == value && !strings.ContainsRune(value, 0)
}

func mountedCensusRootsMatch(roots mountguard.MountedInventory, anchors []string, mounts mountSnapshot) bool {
	if roots.Mounts == nil || roots.ConflictingUUIDs == nil || len(roots.Mounts) != len(anchors) {
		return false
	}
	byAnchor := make(map[string]mountObservation, len(mounts.Mounts))
	for _, mount := range mounts.Mounts {
		byAnchor[mount.MountPoint] = mount
	}
	for i, root := range roots.Mounts {
		mount, exists := byAnchor[root.Anchor]
		if !exists || root.Anchor != anchors[i] || root.MountID == 0 ||
			root.DeviceMajor != mount.DeviceMajor || root.DeviceMinor != mount.DeviceMinor {
			return false
		}
		// root.MountID is statx UNIQUE, not the mountinfo ID; do not equate them.
	}
	return true
}

func sameMountedCensusRoots(a, b mountguard.MountedInventory) bool {
	if a.Mounts == nil || b.Mounts == nil || a.ConflictingUUIDs == nil || b.ConflictingUUIDs == nil ||
		len(a.Mounts) != len(b.Mounts) || len(a.ConflictingUUIDs) != len(b.ConflictingUUIDs) {
		return false
	}
	for i := range a.Mounts {
		if a.Mounts[i] != b.Mounts[i] {
			return false
		}
	}
	for i := range a.ConflictingUUIDs {
		if a.ConflictingUUIDs[i] != b.ConflictingUUIDs[i] {
			return false
		}
	}
	return true
}

func sameMountedCensusArrays(a, b []mdArrayStorageIdentity) bool {
	if a == nil || b == nil || len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.arrayName != y.arrayName || x.arrayUUID != y.arrayUUID || x.arrayMajor != y.arrayMajor ||
			x.arrayMinor != y.arrayMinor || x.arrayDiskSeq != y.arrayDiskSeq || x.level != y.level ||
			len(x.memberDisks) != len(y.memberDisks) {
			return false
		}
		for j := range x.memberDisks {
			if x.memberDisks[j] != y.memberDisks[j] {
				return false
			}
		}
	}
	return true
}

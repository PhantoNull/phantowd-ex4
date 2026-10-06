// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

const maxSwapEntries = 32

var errStorageDiscoveryIncomplete = errors.New("trusted storage discovery is incomplete")

type storageDiscoveryCandidate struct {
	Name         string
	Generation   volumeprobe.BlockDeviceGeneration
	SerialStatus identityStatus
	WWNStatus    identityStatus
}

type storageDiscoveryExclusion struct {
	Name   string
	Reason string
}

type storageDiscoveryPlan struct {
	Candidates                 []storageDiscoveryCandidate
	Excluded                   []storageDiscoveryExclusion
	HasAmbiguousIdentity       bool
	IdentityEvidenceIncomplete bool
}

// trustedStorageDiscovery owns the read-only source descriptors until Close.
// It is an internal, point-in-time assessment, not a storage lease, stable
// identity, compatibility decision, or authorization to mount or mutate.
type trustedStorageDiscovery struct {
	inventory                  storageSnapshot
	mounts                     mountSnapshot
	swap                       swapObservation
	candidates                 []storageDiscoveryCandidate
	excluded                   []storageDiscoveryExclusion
	hasAmbiguousIdentity       bool
	identityEvidenceIncomplete bool
	sources                    []volumeprobe.BlockDeviceSource
	closed                     bool
}

func (discovery *trustedStorageDiscovery) Close() error {
	if discovery == nil || discovery.closed {
		return nil
	}
	discovery.closed = true
	failed := false
	for _, source := range discovery.sources {
		if source.File != nil && source.File.Close() != nil {
			failed = true
		}
	}
	discovery.sources = nil
	if failed {
		return errStorageDiscoveryIncomplete
	}
	return nil
}

type storageSourceOpener func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error)

// planTrustedStorageDiscovery accepts only complete private collector
// snapshots. It includes every non-removable, non-virtual leaf candidate with
// no mount attributed in this process's mount namespace. Known multi-device
// filesystems whose full backing set is not represented by the block graph
// make the assessment incomplete. A candidate with ambiguous or unavailable
// VPD remains in the read-only set, but the plan records that identity
// evidence is not unique/complete. This does not prove global non-use.
func planTrustedStorageDiscovery(storage storageSnapshot, mounts mountSnapshot) (storageDiscoveryPlan, error) {
	allDevices, err := completeObservedBlockDeviceSet(storage)
	if err != nil || !validMountSnapshot(mounts) {
		return storageDiscoveryPlan{}, errStorageDiscoveryIncomplete
	}
	if hasUnsupportedMultiDeviceFilesystem(mounts.Mounts) {
		return storageDiscoveryPlan{}, errStorageDiscoveryIncomplete
	}
	observations := make(map[string]blockObservation, len(storage.Observations))
	for _, observation := range storage.Observations {
		observations[observation.Name] = observation
	}
	plan := storageDiscoveryPlan{
		Candidates: make([]storageDiscoveryCandidate, 0, len(allDevices)),
		Excluded:   make([]storageDiscoveryExclusion, 0, len(allDevices)),
	}
	for _, device := range allDevices {
		observation := observations[device.Name]
		if observation.SerialStatus == identityAmbiguous || observation.WWNStatus == identityAmbiguous {
			plan.HasAmbiguousIdentity = true
		}
		if identityEvidenceMissing(observation.SerialStatus) || identityEvidenceMissing(observation.WWNStatus) {
			plan.IdentityEvidenceIncomplete = true
		}
		reason := ""
		switch {
		case isVirtualBlockTarget(observation.sysfsTarget):
			reason = "virtual-block-node"
		case len(observation.lowerBlocks) != 0:
			reason = "stacked-block-node"
		default:
			stacked, stackErr := wholeDiskHasStackedDependent(observation, storage.Observations)
			if stackErr != nil {
				return storageDiscoveryPlan{}, errStorageDiscoveryIncomplete
			}
			if stacked {
				reason = "member-of-stacked-block-node"
			}
		}
		if reason == "" {
			mounted, mountErr := observedWholeDiskHasVisibleDependentMount(observation, storage.Observations, mounts.Mounts)
			if mountErr != nil {
				return storageDiscoveryPlan{}, errStorageDiscoveryIncomplete
			}
			if mounted {
				reason = "visible-dependent-mount"
			}
		}
		if reason == "" && observation.Removable {
			reason = "removable-device"
		}
		if reason != "" {
			plan.Excluded = append(plan.Excluded, storageDiscoveryExclusion{Name: device.Name, Reason: reason})
			continue
		}
		plan.Candidates = append(plan.Candidates, storageDiscoveryCandidate{
			Name: device.Name, Generation: device.Generation,
			SerialStatus: observation.SerialStatus, WWNStatus: observation.WWNStatus,
		})
	}
	return plan, nil
}

func hasUnsupportedMultiDeviceFilesystem(mounts []mountObservation) bool {
	for _, mount := range mounts {
		switch strings.ToLower(mount.Filesystem) {
		case "btrfs", "bcachefs", "zfs":
			return true
		}
	}
	return false
}

func identityEvidenceMissing(status identityStatus) bool {
	return status == identityUnavailable || status == identityInvalid || status == identityUnreadable
}

func isVirtualBlockTarget(target string) bool {
	return strings.HasPrefix(target, "devices/virtual/block/")
}

func wholeDiskHasStackedDependent(disk blockObservation, inventory []blockObservation) (bool, error) {
	for _, observation := range inventory {
		if observation.Kind != "block" || observation.Name == disk.Name || len(observation.lowerBlocks) == 0 {
			continue
		}
		depends, err := observedBlockNodeDependsOnWholeDisk(observation, disk, inventory)
		if err != nil {
			return false, err
		}
		if depends {
			return true, nil
		}
	}
	return false, nil
}

func validMountSnapshot(snapshot mountSnapshot) bool {
	if snapshot.SchemaVersion != 1 || snapshot.Scope != "current-process-mount-namespace" ||
		!snapshot.ReadOnly || snapshot.FilesystemContentsRead || snapshot.MountOperationsPerformed ||
		!snapshot.collectionComplete ||
		snapshot.ObservedAt.IsZero() || snapshot.Mounts == nil || len(snapshot.Mounts) > maxMountEntries ||
		snapshot.MountCount != len(snapshot.Mounts) {
		return false
	}
	for _, mount := range snapshot.Mounts {
		if mount.MountPoint == "" || mount.MountPoint[0] != '/' || !validMountFilesystem(mount.Filesystem) {
			return false
		}
	}
	return true
}

type swapObservation struct {
	entries  int
	evidence [32]byte
}

// collectSwapObservation treats active swap as an unknown block consumer. It
// refuses the whole assessment instead of trying to infer which devices are
// safe from filenames or swap-file paths.
func collectSwapObservation(proc fs.FS) (swapObservation, error) {
	data, err := readBounded(proc, "swaps")
	if err != nil {
		return swapObservation{}, errStorageDiscoveryIncomplete
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	header := strings.Fields(lines[0])
	if len(header) != 5 || header[0] != "Filename" || header[1] != "Type" ||
		header[2] != "Size" || header[3] != "Used" || header[4] != "Priority" ||
		len(lines)-1 > maxSwapEntries {
		return swapObservation{}, errStorageDiscoveryIncomplete
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] == "" || (fields[1] != "file" && fields[1] != "partition") {
			return swapObservation{}, errStorageDiscoveryIncomplete
		}
		if _, err := strconv.ParseUint(fields[2], 10, 64); err != nil {
			return swapObservation{}, errStorageDiscoveryIncomplete
		}
		if _, err := strconv.ParseUint(fields[3], 10, 64); err != nil {
			return swapObservation{}, errStorageDiscoveryIncomplete
		}
		if _, err := strconv.ParseInt(fields[4], 10, 32); err != nil {
			return swapObservation{}, errStorageDiscoveryIncomplete
		}
	}
	return swapObservation{entries: len(lines) - 1, evidence: sha256.Sum256(data)}, nil
}

// discoverTrustedStorageWith binds a complete sysfs observation to all
// eligible fixed-path read-only descriptors, then rechecks sysfs, the current
// process mount namespace and swap observations before returning any
// descriptor. It refuses mounted multi-device filesystems not represented by
// the observed block graph. The opener is injected to keep host tests
// unprivileged; production/QEMU callers use the fixed /dev opener. It never
// probes filesystem contents or mounts anything, and does not prove global
// userspace or mount-namespace exclusivity.
func discoverTrustedStorageWith(sysfs, proc fs.FS, open storageSourceOpener) (*trustedStorageDiscovery, error) {
	if open == nil {
		return nil, errStorageDiscoveryIncomplete
	}
	beforeStorage, err := collectStorage(sysfs)
	if err != nil {
		return nil, errStorageDiscoveryIncomplete
	}
	beforeMounts, err := collectMountInventory(proc, time.Now())
	if err != nil {
		return nil, errStorageDiscoveryIncomplete
	}
	beforeSwap, err := collectSwapObservation(proc)
	if err != nil || beforeSwap.entries != 0 {
		return nil, errStorageDiscoveryIncomplete
	}
	plan, err := planTrustedStorageDiscovery(beforeStorage, beforeMounts)
	if err != nil {
		return nil, errStorageDiscoveryIncomplete
	}
	devices := make([]volumeprobe.ObservedBlockDevice, 0, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		devices = append(devices, volumeprobe.ObservedBlockDevice{Name: candidate.Name, Generation: candidate.Generation})
	}
	sources, err := open(devices)
	if err != nil {
		closeBlockDeviceSources(sources)
		return nil, errStorageDiscoveryIncomplete
	}
	generations := make([]volumeprobe.BlockDeviceGeneration, len(devices))
	for index := range devices {
		generations[index] = devices[index].Generation
	}
	orderedSources, err := volumeprobe.OrderCompleteBlockSources(generations, sources)
	if err != nil {
		closeBlockDeviceSources(sources)
		return nil, errStorageDiscoveryIncomplete
	}
	afterStorage, err := collectStorage(sysfs)
	if err != nil {
		closeBlockDeviceSources(orderedSources)
		return nil, errStorageDiscoveryIncomplete
	}
	afterMounts, err := collectMountInventory(proc, time.Now())
	if err != nil {
		closeBlockDeviceSources(orderedSources)
		return nil, errStorageDiscoveryIncomplete
	}
	afterSwap, err := collectSwapObservation(proc)
	if err != nil || afterSwap.entries != 0 || beforeSwap != afterSwap ||
		!sameStorageSnapshot(beforeStorage, afterStorage) || !sameMountSnapshot(beforeMounts, afterMounts) {
		closeBlockDeviceSources(orderedSources)
		return nil, errStorageDiscoveryIncomplete
	}
	return &trustedStorageDiscovery{
		inventory: beforeStorage, mounts: beforeMounts, swap: beforeSwap,
		candidates: plan.Candidates, excluded: plan.Excluded,
		hasAmbiguousIdentity:       plan.HasAmbiguousIdentity,
		identityEvidenceIncomplete: plan.IdentityEvidenceIncomplete,
		sources:                    orderedSources,
	}, nil
}

func closeBlockDeviceSources(sources []volumeprobe.BlockDeviceSource) {
	for _, source := range sources {
		if source.File != nil {
			_ = source.File.Close()
		}
	}
}

func sameStorageSnapshot(a, b storageSnapshot) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Scope != b.Scope ||
		a.InventoryReadOnly != b.InventoryReadOnly || a.BlockDevicesOpened != b.BlockDevicesOpened ||
		a.ContentRead != b.ContentRead || a.MutationsPerformed != b.MutationsPerformed ||
		a.StableIdentityAvailable != b.StableIdentityAvailable || a.DeviceCount != b.DeviceCount ||
		a.collectionComplete != b.collectionComplete ||
		len(a.Observations) != len(b.Observations) || len(a.Limitations) != len(b.Limitations) {
		return false
	}
	for index := range a.Limitations {
		if a.Limitations[index] != b.Limitations[index] {
			return false
		}
	}
	for index := range a.Observations {
		if !sameBlockObservation(a.Observations[index], b.Observations[index]) {
			return false
		}
	}
	return true
}

func sameMountSnapshot(a, b mountSnapshot) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Scope != b.Scope || a.ReadOnly != b.ReadOnly ||
		a.FilesystemContentsRead != b.FilesystemContentsRead ||
		a.MountOperationsPerformed != b.MountOperationsPerformed || a.MountCount != b.MountCount ||
		a.collectionComplete != b.collectionComplete ||
		len(a.Mounts) != len(b.Mounts) || len(a.Limitations) != len(b.Limitations) {
		return false
	}
	for index := range a.Limitations {
		if a.Limitations[index] != b.Limitations[index] {
			return false
		}
	}
	for index := range a.Mounts {
		if a.Mounts[index] != b.Mounts[index] {
			return false
		}
	}
	return true
}

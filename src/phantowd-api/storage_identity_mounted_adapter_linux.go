//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"

// correlateObservedMountedStorageIdentity bridges the Linux mount observation
// to the platform-neutral, side-effect-free identity correlation.
func correlateObservedMountedStorageIdentity(storage storageSnapshot, arrays []mdArrayStorageIdentity, observed mountguard.MountedInventory) ([]mountedStorageIdentity, error) {
	inventory := mountedFilesystemInventory{
		mounts:           make([]mountedFilesystemObservation, len(observed.Mounts)),
		conflictingUUIDs: append([]string{}, observed.ConflictingUUIDs...),
	}
	for index, mount := range observed.Mounts {
		inventory.mounts[index] = mountedFilesystemObservation{
			anchor: mount.Anchor, filesystemUUID: mount.FilesystemUUID, mountID: mount.MountID,
			deviceMajor: mount.DeviceMajor, deviceMinor: mount.DeviceMinor,
		}
	}
	return correlateMountedStorageIdentity(storage, arrays, inventory)
}

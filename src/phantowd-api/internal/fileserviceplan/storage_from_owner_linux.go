//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"path"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// StorageFromMountedOwnerSet converts one lock-coherent, all-or-error
// observation from the fixed M3.4 Owner roster into planner evidence. Complete
// means complete for that trusted roster, not proof that the roster itself
// covers every physical disk or every possible volume on the appliance.
func StorageFromMountedOwnerSet(evidence mountowner.MountedVolumeSetEvidence) (StorageSnapshot, error) {
	observed := evidence.Volumes()
	if !evidence.Complete() || evidence.Generation() == 0 || evidence.Fingerprint() == [32]byte{} ||
		observed == nil || len(observed) == 0 || len(observed) > MaxObservedVolumes {
		return StorageSnapshot{}, ErrNotReady
	}

	volumes := make([]ObservedVolume, len(observed))
	policyVolumes := make([]shareconfig.Volume, len(observed))
	for index, volume := range observed {
		id := shareconfig.VolumeID(volume.VolumeID())
		uuid := shareconfig.FilesystemUUID(volume.FilesystemUUID())
		if volume.Compatibility() != CompatibilityQualified ||
			volume.MountPath() != path.Join(shareconfig.VolumeMountRoot, string(id)) ||
			volume.Generation() == 0 || volume.MountID() == 0 || volume.DeviceMajor() == 0 ||
			validateLogicalVolume(id, uuid) != nil {
			return StorageSnapshot{}, ErrInvalidEvidence
		}
		volumes[index] = ObservedVolume{
			VolumeID: id, FilesystemUUID: uuid, MountPath: volume.MountPath(),
			Compatibility: volume.Compatibility(), MountID: volume.MountID(),
			DeviceMajor: volume.DeviceMajor(), DeviceMinor: volume.DeviceMinor(), ReadOnly: volume.ReadOnly(),
		}
		policyVolumes[index] = shareconfig.Volume{ID: id, FilesystemUUID: uuid}
	}

	snapshot := StorageSnapshot{
		Complete: true, Generation: evidence.Generation(), OwnerFingerprint: evidence.Fingerprint(), Volumes: volumes,
	}
	if err := validateStorageSnapshot(snapshot, shareconfig.Config{Volumes: policyVolumes}); err != nil {
		return StorageSnapshot{}, err
	}
	return snapshot, nil
}

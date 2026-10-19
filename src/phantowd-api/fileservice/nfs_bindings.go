// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"

// ValidateRetainedNFSBindings checks two complete desired documents. An export
// ID present in both must retain its logical volume, filesystem UUID and root.
// Client/access changes, additions and removals remain ordinary desired edits.
// This is NOT a lifetime reservation ledger: an ID absent from the current
// document has no historical binding here. CAS, retirement history, runtime
// consumers and service admission require their own qualified owner protocol.
func ValidateRetainedNFSBindings(current, next Config) error {
	if current.Validate() != nil || next.Validate() != nil {
		return ErrConfig
	}
	type binding struct {
		volume shareconfig.Volume
		root   string
	}
	volumes := func(config Config) map[shareconfig.VolumeID]shareconfig.Volume {
		result := make(map[shareconfig.VolumeID]shareconfig.Volume, len(config.Shares.Volumes))
		for _, volume := range config.Shares.Volumes {
			result[volume.ID] = volume
		}
		return result
	}
	previousVolumes, nextVolumes := volumes(current), volumes(next)
	previous := make(map[string]binding, len(current.NFS.Exports))
	for _, export := range current.NFS.Exports {
		previous[export.ID] = binding{previousVolumes[export.VolumeID], export.RelativePath}
	}
	for _, export := range next.NFS.Exports {
		if old, exists := previous[export.ID]; exists &&
			old != (binding{nextVolumes[export.VolumeID], export.RelativePath}) {
			return ErrConfig
		}
	}
	return nil
}

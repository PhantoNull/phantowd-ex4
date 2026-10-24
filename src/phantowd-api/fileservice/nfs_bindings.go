// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

// ValidateRetainedNFSBindings compares sources only for export IDs present in
// both desired documents. It provides no historical ID ledger or service authority.
func ValidateRetainedNFSBindings(current, next Config) error {
	if current.Validate() != nil || next.Validate() != nil {
		return ErrConfig
	}
	bindings := func(c Config) map[string][3]string {
		result := make(map[string][3]string, len(c.NFS.Exports))
		for _, export := range c.NFS.Exports {
			for _, volume := range c.Shares.Volumes {
				if volume.ID == export.VolumeID {
					result[export.ID] = [3]string{string(volume.ID), string(volume.FilesystemUUID), export.RelativePath}
				}
			}
		}
		return result
	}
	previous := bindings(current)
	for id, source := range bindings(next) {
		if old, retained := previous[id]; retained && old != source {
			return ErrConfig
		}
	}
	return nil
}

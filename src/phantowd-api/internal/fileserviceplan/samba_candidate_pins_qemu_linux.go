//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"

// VerifySharePinsQEMU checks that the live trusted handoff retains exactly this
// complete candidate's ID/volume/path/RO requests. It supplies no write/mount
// operation and transfers no ownership. The eventual coordinator must ALSO recompile
// fresh storage/identity evidence and keep both authorities through verified
// stop and copied-descriptor closure. This check is not launch authorization.
func (c SambaIsolatedCandidate) VerifySharePinsQEMU(pins *mountowner.ServiceSharePinsQEMU) error {
	if !c.valid || pins == nil {
		return ErrNotReady
	}
	required := make([]mountowner.ServiceShare, len(c.roots))
	for index, root := range c.roots {
		required[index] = mountowner.ServiceShare{ID: root.ID, VolumeID: string(root.VolumeID),
			RelativePath: root.RelativePath, ReadOnly: root.ReadOnly}
	}
	return pins.VerifyDeclaredRoots(required)
}

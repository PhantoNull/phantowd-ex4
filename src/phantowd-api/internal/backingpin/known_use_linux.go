//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

// A private negative admission gate, never global-use/activation authority.
// Only canonical configured paths and SAME logical VolumeID are compared;
// actual aliases, other processes/targets and filesystem access need separate
// retained observations/ownership. Desired-policy validation/save/review remain
// unchanged and do not activate services. Inputs must be stable under caller
// ownership; the complete-target Owner supplies its own coherent policy claim.
func knownTargetUseAllowed(document naspolicy.Config, id iscsipolicy.TargetID) bool {
	if document.Validate() != nil {
		return false
	}
	definitions := make(map[iscsipolicy.BackingID]iscsipolicy.Backing, len(document.ISCSI.Backings))
	for _, backing := range document.ISCSI.Backings {
		definitions[backing.ID] = backing
	}
	for _, target := range document.ISCSI.Targets {
		if target.ID != id {
			continue
		}
		for _, lun := range target.LUNs {
			backing, found := definitions[lun.BackingID]
			if !found || !knownBackingPathIsolated(document, backing) {
				return false
			}
		}
		return true
	}
	return false
}

// Called only after complete document validation. Even a read-only share must
// not expose a live LUN backing. Grant/access/state are not exclusion evidence.
func knownBackingPathIsolated(document naspolicy.Config, backing iscsipolicy.Backing) bool {
	overlap := func(a, b string) bool {
		return a == "." || b == "." || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
	}
	for _, share := range document.FileServices.Shares.Shares {
		if share.VolumeID == backing.VolumeID && overlap(share.RelativePath, backing.RelativePath) {
			return false
		}
	}
	for _, export := range document.FileServices.NFS.Exports {
		if export.VolumeID == backing.VolumeID && overlap(export.RelativePath, backing.RelativePath) {
			return false
		}
	}
	return true
}

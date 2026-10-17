// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicy

import (
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// ReplaceFileServices builds one next-revision desired document, preserving all
// iSCSI definitions except their revision bindings. Both inputs must be valid;
// next must explicitly carry base+1 throughout its component revisions. Removing
// or rebinding a volume still referenced by iSCSI refuses the entire edit.
// No I/O, store/CAS,
// migration, backing/credential opening or service permission is supplied here.
// Inputs must not change concurrently; the result owns independent values.
func ReplaceFileServices(base Config, next fileservice.Config) (Config, error) {
	if base.Validate() != nil || base.Revision == ^uint64(0) || next.Revision != base.Revision+1 {
		return Config{}, ErrInvalid
	}
	c := base
	c.Revision = next.Revision
	c.FileServices = next
	c.ISCSI.Revision = next.Revision
	c.ISCSI.VolumeRevision = next.Revision
	if c.Validate() != nil {
		return Config{}, ErrInvalid
	}
	// Retained iSCSI references must retain their volume definitions too. An
	// unchanged VolumeID with a different filesystem would otherwise silently
	// redirect a LUN while leaving every iSCSI field byte-for-byte unchanged.
	nextVolumes := make(map[shareconfig.VolumeID]shareconfig.Volume, len(next.Shares.Volumes))
	for _, volume := range next.Shares.Volumes {
		nextVolumes[volume.ID] = volume
	}
	for _, backing := range base.ISCSI.Backings {
		for _, volume := range base.FileServices.Shares.Volumes {
			if backing.VolumeID == volume.ID && nextVolumes[volume.ID] != volume {
				return Config{}, ErrInvalid
			}
		}
	}
	return detachedValues(c), nil
}

// ReplaceISCSI is the other view of the same desired document. SMB/NFS content
// is retained and only its revision bindings advance. It cannot authorize LIO,
// file allocation, network access, credentials or store publication.
func ReplaceISCSI(base Config, next iscsipolicy.Policy) (Config, error) {
	if base.Validate() != nil || base.Revision == ^uint64(0) || next.Revision != base.Revision+1 {
		return Config{}, ErrInvalid
	}
	c := base
	c.Revision = next.Revision
	c.FileServices.Revision = next.Revision
	c.FileServices.Shares.Revision = next.Revision
	c.FileServices.NFS.Revision = next.Revision
	c.FileServices.NFS.VolumeRevision = next.Revision
	c.ISCSI = next
	if c.Validate() != nil {
		return Config{}, ErrInvalid
	}
	return detachedValues(c), nil
}

// Keep every model validation, including child encoded-size and nil-collection
// checks, without decoding the complete JSON twice per manual edit. All mutable
// reference fields are cloned; strings/scalars are immutable value data. Extend
// this list and its independence tests when a model gains reference fields.
func detachedValues(c Config) Config {
	shares := &c.FileServices.Shares
	shares.Volumes = slices.Clone(shares.Volumes)
	shares.Users = slices.Clone(shares.Users)
	shares.Shares = slices.Clone(shares.Shares)
	for i := range shares.Shares {
		shares.Shares[i].Grants = slices.Clone(shares.Shares[i].Grants)
	}
	c.FileServices.NFS.Exports = slices.Clone(c.FileServices.NFS.Exports)
	for i := range c.FileServices.NFS.Exports {
		c.FileServices.NFS.Exports[i].Clients = slices.Clone(c.FileServices.NFS.Exports[i].Clients)
	}
	c.ISCSI.Backings = slices.Clone(c.ISCSI.Backings)
	c.ISCSI.Targets = slices.Clone(c.ISCSI.Targets)
	for i := range c.ISCSI.Targets {
		target := &c.ISCSI.Targets[i]
		target.LUNs = slices.Clone(target.LUNs)
		target.Initiators = slices.Clone(target.Initiators)
		for j := range target.Initiators {
			target.Initiators[j].Grants = slices.Clone(target.Initiators[j].Grants)
		}
	}
	return c
}

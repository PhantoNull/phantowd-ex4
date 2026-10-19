// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"errors"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

// NFSExportRoot is a request, not a retained mount or export authority. Volume
// preserves the SAME Plan's observed tuple; Clients preserves per-client rules.
// A mixed export requires writable storage without granting every client RW.
type NFSExportRoot struct {
	ID           string
	Volume       VolumeBinding
	RelativePath string
	ReadOnly     bool
	Clients      []nfsconfig.Client
}

// NFSv3Candidate is fixed to TCP/AUTH_SYS. It is immutable and non-serializable,
// not a service lease, parser qualification or permission to control the kernel.
type NFSv3Candidate struct {
	table     string
	roots     []NFSExportRoot
	freshness Freshness
	valid     bool
}

func (p Plan) NFSv3TCPCandidate() (NFSv3Candidate, error) {
	if p.scope != "candidate-only" {
		return NFSv3Candidate{}, ErrNotReady
	}
	for _, root := range p.nfsRoots {
		for _, client := range root.Clients {
			if client.Security != "sys" {
				return NFSv3Candidate{}, ErrNotReady
			}
		}
	}
	return NFSv3Candidate{table: p.nfsConfig, roots: p.nfsRoots, freshness: p.freshness, valid: true}, nil
}

// Documents returns independent copies. A valid empty policy means disabled:
// no table or roots are supplied for service startup. The zero value refuses.
func (c NFSv3Candidate) Documents() (enabled bool, table string, roots []NFSExportRoot, err error) {
	if !c.valid {
		return false, "", nil, ErrNotReady
	}
	if len(c.roots) == 0 {
		return false, "", []NFSExportRoot{}, nil
	}
	roots = slices.Clone(c.roots)
	for index := range roots {
		roots[index].Clients = slices.Clone(roots[index].Clients)
	}
	return true, c.table, roots, nil
}

func (c NFSv3Candidate) FreshAgainst(current Freshness) bool {
	return c.valid && c.freshness == current
}

// FreshAgainstStorage compares DATA only; it supplies no retained authority.
// A trusted consumer must obtain the snapshot from its original roster lease.
func (c NFSv3Candidate) FreshAgainstStorage(s StorageSnapshot) bool {
	return c.valid && s.Complete && s.Generation > 0 && s.Volumes != nil &&
		len(s.Volumes) <= MaxObservedVolumes && c.freshness.StorageGeneration == s.Generation &&
		c.freshness.StorageFingerprint == fingerprintStorageSnapshot(s)
}

func (NFSv3Candidate) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal NFS candidate is not serializable")
}

func (*NFSv3Candidate) UnmarshalJSON([]byte) error {
	return errors.New("internal NFS candidate cannot be deserialized")
}

func nfsCandidateRoots(policy nfsconfig.Policy, volumes []VolumeBinding) ([]NFSExportRoot, error) {
	roots := make([]NFSExportRoot, 0, len(policy.Exports))
	for _, export := range policy.Exports {
		index := slices.IndexFunc(volumes, func(volume VolumeBinding) bool { return volume.VolumeID == export.VolumeID })
		if index < 0 {
			return nil, ErrInvalidEvidence
		}
		readOnly := true
		for _, client := range export.Clients {
			readOnly = readOnly && client.Access != "rw"
		}
		clients := slices.Clone(export.Clients)
		slices.SortFunc(clients, func(a, b nfsconfig.Client) int { return strings.Compare(a.Network, b.Network) })
		roots = append(roots, NFSExportRoot{ID: export.ID, Volume: volumes[index], RelativePath: export.RelativePath,
			ReadOnly: readOnly, Clients: clients})
	}
	slices.SortFunc(roots, func(a, b NFSExportRoot) int { return strings.Compare(a.ID, b.ID) })
	return roots, nil
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/smbconfig"
)

// SambaShareRoot is a fixed request for a future descriptor-based mount
// handoff. It is not an open directory, a lease or an authorization token.
// ReadOnly means there are no RW grants in this share's validated policy;
// a mixed share needs a writable clone plus separate Samba/Unix enforcement.
type SambaShareRoot struct {
	ID           string
	VolumeID     shareconfig.VolumeID
	RelativePath string
	ReadOnly     bool
}

// SambaShareCandidates returns isolated sections and their exact declared
// source roots from the same immutable Plan as its NSS/freshness evidence.
// It does no I/O. The eventual coordinator must acquire the complete roster,
// revalidate identity/storage and attach retained descriptors at /shares/<id>
// before launch. An ordinary candidate's host paths are never a fallback.
func (p Plan) SambaShareCandidates() (string, []SambaShareRoot, error) {
	if p.scope != "candidate-only" {
		return "", nil, ErrNotReady
	}
	preview, err := smbconfig.BuildIsolated(p.sambaPolicy)
	if err != nil {
		return "", nil, ErrNotReady
	}
	roots := make([]SambaShareRoot, 0, len(p.sambaPolicy.Shares))
	for _, share := range p.sambaPolicy.Shares {
		readOnly := true
		for _, grant := range share.Grants {
			if grant.Access == "rw" {
				readOnly = false
			}
		}
		roots = append(roots, SambaShareRoot{
			ID: share.ID, VolumeID: share.VolumeID, RelativePath: share.RelativePath, ReadOnly: readOnly,
		})
	}
	slices.SortFunc(roots, func(a, b SambaShareRoot) int { return strings.Compare(a.ID, b.ID) })
	return preview.Sections, roots, nil
}

func cloneSambaPolicy(policy shareconfig.Config) shareconfig.Config {
	policy.Volumes = slices.Clone(policy.Volumes)
	policy.Users = slices.Clone(policy.Users)
	policy.Shares = slices.Clone(policy.Shares)
	for index := range policy.Shares {
		policy.Shares[index].Grants = slices.Clone(policy.Shares[index].Grants)
	}
	return policy
}

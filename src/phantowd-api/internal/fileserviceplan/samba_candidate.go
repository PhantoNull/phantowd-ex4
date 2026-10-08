// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"errors"
	"slices"
)

// SambaIsolatedCandidate binds private lookup, isolated grant sections and
// exact root requests to ONE complete Plan. It is immutable candidate evidence,
// not a mount lease or launch authority. No caller-selected document may replace
// one part while preserving this candidate's freshness.
type SambaIsolatedCandidate struct {
	passwd, group, nss, sections string
	roots                        []SambaShareRoot
	freshness                    Freshness
	valid                        bool
}

func (p Plan) SambaIsolatedCandidate() (SambaIsolatedCandidate, error) {
	passwd, group, nss, err := p.SambaNSSCandidates()
	if err != nil {
		return SambaIsolatedCandidate{}, err
	}
	sections, roots, err := p.SambaShareCandidates()
	if err != nil || len(roots) == 0 {
		return SambaIsolatedCandidate{}, ErrNotReady
	}
	return SambaIsolatedCandidate{passwd: passwd, group: group, nss: nss,
		sections: sections, roots: roots, freshness: p.freshness, valid: true}, nil
}

// Documents returns fresh caller-owned containers. Globals, code/state/profile
// admission and runtime validation remain the service constructor's job.
func (c SambaIsolatedCandidate) Documents() (passwd, group, nss, sections string, roots []SambaShareRoot, err error) {
	if !c.valid {
		return "", "", "", "", nil, ErrNotReady
	}
	return c.passwd, c.group, c.nss, c.sections, slices.Clone(c.roots), nil
}

func (c SambaIsolatedCandidate) FreshAgainst(current Freshness) bool {
	return c.valid && c.freshness == current
}

func (SambaIsolatedCandidate) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal isolated Samba candidate is not serializable")
}

func (*SambaIsolatedCandidate) UnmarshalJSON([]byte) error {
	return errors.New("internal isolated Samba candidate cannot be deserialized")
}

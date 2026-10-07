// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"errors"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

type sambaLookupDocuments struct {
	passwd, group, nss string
}

// SambaRoleCandidate keeps complete native management lookup distinct from
// granted-only service lookup, derived from ONE Plan and freshness tuple.
// It is inert immutable evidence, not configuration/state/identity authority.
// It neither replaces enrollment lookup nor admits workers or a daemon.
type SambaRoleCandidate struct {
	management sambaLookupDocuments
	service    SambaIsolatedCandidate
	valid      bool
}

// sambaManagementLookup is optional at Build: a share-only Plan may be valid
// without ungranted Unix identities. Such a Plan must not yield a two-role
// candidate. Disabled live accounts need management lookup; retired accounts
// retain their registry reservations but never become lookup rows here.
func sambaManagementLookup(snapshot IdentitySnapshot) sambaLookupDocuments {
	accounts := make([]serviceaccounts.Account, 0, serviceaccounts.MaxLive)
	for _, account := range snapshot.Registry.Accounts {
		if account.State == serviceaccounts.Retired {
			continue
		}
		if !slices.Contains(snapshot.UnixUIDs, account.UID) || !slices.Contains(snapshot.UnixGIDs, account.GID) {
			return sambaLookupDocuments{}
		}
		accounts = append(accounts, account)
	}
	passwd, group, nss, err := renderNativeSambaNSS(accounts)
	if err != nil {
		return sambaLookupDocuments{}
	}
	return sambaLookupDocuments{passwd: passwd, group: group, nss: nss}
}

// SambaRoleCandidate cannot pair separately supplied candidates. BuildFromOwners
// derives both views while the ordered storage and identity locks are held;
// Build still accepts caller-supplied snapshots and is not an authority boundary.
// Native confirmation comes from that trusted Owner adapter, not these strings.
func (p Plan) SambaRoleCandidate() (SambaRoleCandidate, error) {
	if p.scope != "candidate-only" || p.sambaManagementNSS.passwd == "" ||
		p.sambaManagementNSS.group == "" || p.sambaManagementNSS.nss == "" {
		return SambaRoleCandidate{}, ErrNotReady
	}
	service, err := p.SambaIsolatedCandidate()
	if err != nil {
		return SambaRoleCandidate{}, err
	}
	return SambaRoleCandidate{management: p.sambaManagementNSS, service: service, valid: true}, nil
}

func (c SambaRoleCandidate) ManagementDocuments() (passwd, group, nss string, err error) {
	if !c.valid {
		return "", "", "", ErrNotReady
	}
	return c.management.passwd, c.management.group, c.management.nss, nil
}

func (c SambaRoleCandidate) ServiceCandidate() (SambaIsolatedCandidate, error) {
	if !c.valid {
		return SambaIsolatedCandidate{}, ErrNotReady
	}
	return c.service, nil
}

func (c SambaRoleCandidate) FreshAgainst(current Freshness) bool {
	return c.valid && c.service.FreshAgainst(current)
}

func (SambaRoleCandidate) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal Samba role candidate is not serializable")
}

func (*SambaRoleCandidate) UnmarshalJSON([]byte) error {
	return errors.New("internal Samba role candidate cannot be deserialized")
}

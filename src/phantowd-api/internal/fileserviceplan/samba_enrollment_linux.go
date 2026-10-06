//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// SambaEnrollmentLookup is an immutable native lookup candidate, deliberately
// not a Plan or IdentitySnapshot. It includes confirmed disabled native accounts
// without asserting passdb absence, credentials or share authorization. It does
// not install files, pin the Owner, stage state or authorize a service launch.
type SambaEnrollmentLookup struct {
	passwd, group, nss string
	fingerprint        [32]byte
}

// SambaEnrollmentLookupFromOwner derives the candidate under the same lock as
// native/Samba mutations. Only bounded in-process rendering occurs in the lock;
// a later constructor must independently qualify staging, freshness and lifetime.
func SambaEnrollmentLookupFromOwner(ctx context.Context, owner *identityowner.Owner) (SambaEnrollmentLookup, error) {
	if ctx == nil || owner == nil {
		return SambaEnrollmentLookup{}, ErrNotReady
	}
	var lookup SambaEnrollmentLookup
	err := owner.WithNativeLookupSnapshot(ctx, func(evidence identityowner.NativeLookupSnapshot) error {
		var err error
		lookup, err = sambaEnrollmentFromEvidence(evidence)
		return err
	})
	if err != nil {
		return SambaEnrollmentLookup{}, err
	}
	return lookup, nil
}

func sambaEnrollmentFromEvidence(evidence identityowner.NativeLookupSnapshot) (SambaEnrollmentLookup, error) {
	if evidence.Registry.Validate() != nil || evidence.Fingerprint == [32]byte{} ||
		evidence.Native == nil || evidence.Samba == nil || evidence.UIDs == nil || evidence.GIDs == nil || evidence.Names == nil ||
		len(evidence.Native) != len(evidence.Registry.Accounts) || len(evidence.Registry.Accounts) > serviceaccounts.MaxLive ||
		len(evidence.UIDs) > 65536 || len(evidence.GIDs) > 65536 || len(evidence.Names) > 65536 {
		return SambaEnrollmentLookup{}, ErrNotReady
	}
	native := make(map[string]identityprovision.Journal, len(evidence.Native))
	for i, account := range evidence.Registry.Accounts {
		journal := evidence.Native[i]
		if account.State == serviceaccounts.Retired || journal.Validate() != nil || journal.Phase != identityprovision.UnixConfirmed ||
			!sameOwnerAccount(journal.Account, account) || !slices.Contains(evidence.UIDs, account.UID) ||
			!slices.Contains(evidence.GIDs, account.GID) || !slices.Contains(evidence.Names, account.Name) {
			return SambaEnrollmentLookup{}, ErrInvalidEvidence
		}
		native[account.ID] = journal
	}
	seen := make(map[string]bool, len(evidence.Samba))
	for _, journal := range evidence.Samba {
		confirmed, exists := native[journal.Account.ID]
		if !exists || seen[journal.Account.ID] || journal.Validate() != nil ||
			!sameOwnerAccount(journal.Account, confirmed.Account) || journal.NativeRevision != confirmed.Revision {
			return SambaEnrollmentLookup{}, ErrInvalidEvidence
		}
		switch journal.Phase {
		case smbprovision.Reserved, smbprovision.DisabledNoPassword, smbprovision.CredentialSetDisabled,
			smbprovision.Enabled, smbprovision.Disabled:
		default:
			return SambaEnrollmentLookup{}, ErrNotReady
		}
		seen[journal.Account.ID] = true
	}
	passwd, group, nss, err := renderNativeSambaNSS(evidence.Registry.Accounts)
	if err != nil {
		return SambaEnrollmentLookup{}, err
	}
	return SambaEnrollmentLookup{passwd: passwd, group: group, nss: nss, fingerprint: evidence.Fingerprint}, nil
}

func (l SambaEnrollmentLookup) LookupDocuments() (passwd, group, nss string, err error) {
	if l.fingerprint == [32]byte{} || l.passwd == "" || l.group == "" || l.nss == "" {
		return "", "", "", ErrNotReady
	}
	return l.passwd, l.group, l.nss, nil
}

func (l SambaEnrollmentLookup) Fingerprint() [32]byte { return l.fingerprint }

func (SambaEnrollmentLookup) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal Samba enrollment lookup is not serializable")
}

func (*SambaEnrollmentLookup) UnmarshalJSON([]byte) error {
	return errors.New("internal Samba enrollment lookup cannot be deserialized")
}

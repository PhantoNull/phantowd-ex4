//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// IdentityFromOwner obtains fresh identity evidence under the single identity
// Owner lock and adapts it for the pure candidate planner. Registry revision
// is the coarse generation; the evidence fingerprint also binds Unix census,
// native/Samba journals and the batched live passdb observation so unrelated
// identity changes cannot leave a candidate fresh by revision coincidence.
//
// The returned snapshot is process-local and must not be serialized or
// accepted from an HTTP/RPC caller. A later apply-capable owner must collect
// it again and compare the complete Freshness value at its transaction edge.
func IdentityFromOwner(ctx context.Context, owner *identityowner.Owner) (IdentitySnapshot, error) {
	if ctx == nil || owner == nil {
		return IdentitySnapshot{}, ErrNotReady
	}
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return IdentitySnapshot{}, err
	}
	return identityFromOwnerEvidence(evidence)
}

func identityFromOwnerEvidence(evidence identityowner.FileServiceSnapshot) (IdentitySnapshot, error) {
	if evidence.Registry.Validate() != nil || evidence.Fingerprint == [32]byte{} ||
		evidence.Native == nil || evidence.UIDs == nil || evidence.GIDs == nil || evidence.Names == nil ||
		evidence.Samba == nil || evidence.Passdb == nil ||
		len(evidence.Native) != len(evidence.Registry.Accounts) ||
		len(evidence.Passdb) != len(evidence.Registry.Accounts) {
		return IdentitySnapshot{}, ErrNotReady
	}
	for i, account := range evidence.Registry.Accounts {
		journal := evidence.Native[i]
		passdb := evidence.Passdb[i]
		if journal.Validate() != nil || journal.Phase != identityprovision.UnixConfirmed ||
			!sameOwnerAccount(journal.Account, account) ||
			passdb.AccountID != account.ID || !validOwnerObservation(account, passdb.Observation) {
			return IdentitySnapshot{}, ErrInvalidEvidence
		}
	}

	registry := evidence.Registry
	registry.Accounts = slices.Clone(evidence.Registry.Accounts)
	samba := make([]SambaIdentity, len(evidence.Samba))
	for i, identity := range evidence.Samba {
		samba[i] = SambaIdentity{Journal: identity.Journal, Observation: identity.Observation}
	}
	return IdentitySnapshot{
		Complete: true, Generation: evidence.Registry.Revision, Fingerprint: evidence.Fingerprint,
		Registry: registry, UnixUIDs: slices.Clone(evidence.UIDs), UnixGIDs: slices.Clone(evidence.GIDs),
		Samba: samba, KerberosReady: false,
	}, nil
}

func sameOwnerAccount(first, second serviceaccounts.Account) bool {
	return first.ID == second.ID && first.Name == second.Name && first.UID == second.UID && first.GID == second.GID
}

func validOwnerObservation(account serviceaccounts.Account, observation smbprovision.Observation) bool {
	if !observation.Present {
		return observation == (smbprovision.Observation{})
	}
	return observation.Name == account.Name && observation.UID == account.UID && observation.GID == account.GID &&
		observation.SID != ""
}

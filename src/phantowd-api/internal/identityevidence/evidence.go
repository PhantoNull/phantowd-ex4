// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package identityevidence compares stored identity documents without opening
// an Owner, recovering journals or observing/changing Unix or Samba runtime.
package identityevidence

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const MaxInputBytes = 4 << 20

var ErrInvalid = errors.New("invalid stored identity evidence")

// Entry names one account role, NOT a path. The supplied roster must be complete
// and immutable during Match. This DATA API cannot establish that provenance.
type Entry struct {
	AccountID     string
	Native, Samba policyevidence.Slot
}

func (Entry) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*Entry) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (Entry) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "identity-entry{redacted}") }

type Kind string

const (
	NoRecordedRegistry       Kind = "no-recorded-registry"
	StoredLinksObserved      Kind = "stored-links-observed"
	IncompleteDocuments      Kind = "incomplete-identity-documents"
	InconsistentDocuments    Kind = "inconsistent-identity-documents"
	UnresolvedOperation      Kind = "unresolved-identity-operation"
	UnsupportedRegistryState Kind = "unsupported-registry-state"
)

// Every kind permits NO action, including StoredLinksObserved and empty state.
// No account names, identifiers, SID, journal or mutable input escapes.
type Diagnosis struct{ kind Kind }

func (d Diagnosis) Kind() Kind                 { return d.kind }
func (Diagnosis) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*Diagnosis) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (d Diagnosis) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity-observation{"+string(d.kind)+"}")
}

func validSlot(s policyevidence.Slot, limit int) bool {
	return (s.State == policyevidence.Absent || s.State == policyevidence.Unavailable) && len(s.Data) == 0 ||
		s.State == policyevidence.Present && len(s.Data) > 0 && len(s.Data) <= limit
}

func sameIdentity(a, b serviceaccounts.Account) bool {
	return a.ID == b.ID && a.Name == b.Name && a.UID == b.UID && a.GID == b.GID
}

// Match reuses the original strict registry/native/enrollment decoders. It does
// no filesystem/runtime I/O, pending promotion, recovery, enrollment or admission.
// All present documents are decoded before diagnoses; absence cannot hide a
// malformed later record. Unknown state/invalid bytes return only a zero result.
func Match(registry policyevidence.Slot, entries []Entry) (Diagnosis, error) {
	if !validSlot(registry, serviceaccounts.MaxInputBytes) || entries == nil || len(entries) > serviceaccounts.MaxRecords {
		return Diagnosis{}, ErrInvalid
	}
	remaining := MaxInputBytes - len(registry.Data)
	for _, e := range entries {
		if len(e.AccountID) == 0 || len(e.AccountID) > 64 || !validSlot(e.Native, identityprovision.MaxBytes) || !validSlot(e.Samba, smbprovision.MaxBytes) {
			return Diagnosis{}, ErrInvalid
		}
		for _, size := range []int{len(e.AccountID), len(e.Native.Data), len(e.Samba.Data)} {
			if size > remaining {
				return Diagnosis{}, ErrInvalid
			}
			remaining -= size
		}
	}
	var r serviceaccounts.Registry
	var err error
	if registry.State == policyevidence.Present {
		r, err = serviceaccounts.Decode(bytes.NewReader(registry.Data))
		if err != nil {
			return Diagnosis{}, ErrInvalid
		}
	}
	type decoded struct {
		entry  Entry
		native identityprovision.Journal
		samba  smbprovision.Journal
	}
	rows := make(map[string]decoded, len(entries))
	inconsistent := false
	sids := make(map[string]bool, len(entries))
	for _, e := range entries {
		d := decoded{entry: e}
		if e.Native.State == policyevidence.Present {
			d.native, err = identityprovision.Decode(bytes.NewReader(e.Native.Data))
			if err != nil {
				return Diagnosis{}, ErrInvalid
			}
			inconsistent = inconsistent || d.native.Account.ID != e.AccountID
		}
		if e.Samba.State == policyevidence.Present {
			d.samba, err = smbprovision.Decode(bytes.NewReader(e.Samba.Data))
			if err != nil {
				return Diagnosis{}, ErrInvalid
			}
			inconsistent = inconsistent || d.samba.Account.ID != e.AccountID
			if d.samba.SID != "" {
				inconsistent = inconsistent || sids[d.samba.SID]
				sids[d.samba.SID] = true
			}
		}
		if e.Native.State == policyevidence.Present && e.Samba.State == policyevidence.Present {
			inconsistent = inconsistent || !sameIdentity(d.native.Account, d.samba.Account) ||
				d.native.Phase != identityprovision.UnixConfirmed || d.samba.NativeRevision != d.native.Revision
		}
		_, duplicate := rows[e.AccountID]
		inconsistent = inconsistent || duplicate
		rows[e.AccountID] = d
	}
	if inconsistent {
		return Diagnosis{InconsistentDocuments}, nil
	}
	if registry.State == policyevidence.Unavailable {
		return Diagnosis{IncompleteDocuments}, nil
	}
	if registry.State == policyevidence.Absent {
		if len(rows) != 0 {
			return Diagnosis{InconsistentDocuments}, nil
		}
		return Diagnosis{NoRecordedRegistry}, nil
	}
	inconsistent = r.Revision < uint64(len(r.Accounts))+1
	incomplete, unresolved, unsupported := false, false, false
	known := make(map[string]bool, len(r.Accounts))
	var prior uint64
	active := 0
	for i, account := range r.Accounts {
		known[account.ID] = true
		unsupported = unsupported || account.State == serviceaccounts.Retired
		d, found := rows[account.ID]
		if found && d.entry.Samba.State == policyevidence.Present {
			inconsistent = inconsistent || !sameIdentity(d.samba.Account, account)
		}
		if !found || d.entry.Native.State != policyevidence.Present {
			incomplete = true
			continue
		}
		j := d.native
		inconsistent = inconsistent || !sameIdentity(j.Account, account) || j.RegistryRevision < uint64(i)+2 ||
			j.RegistryRevision > r.Revision || j.RegistryRevision <= prior
		prior = j.RegistryRevision
		if j.Phase != identityprovision.UnixConfirmed {
			active++
			unresolved = true
			inconsistent = inconsistent || j.RegistryRevision != r.Revision || active > 1
		}
		if d.entry.Samba.State == policyevidence.Unavailable {
			incomplete = true
		}
		if d.entry.Samba.State == policyevidence.Present {
			s := d.samba
			switch s.Phase {
			case smbprovision.CreateIntent, smbprovision.PasswordIntent, smbprovision.EnableIntent, smbprovision.DisableIntent, smbprovision.ReviewRequired:
				unresolved = true
			}
		}
	}
	for id := range rows {
		inconsistent = inconsistent || !known[id]
	}
	switch {
	case inconsistent:
		return Diagnosis{InconsistentDocuments}, nil
	case incomplete:
		return Diagnosis{IncompleteDocuments}, nil
	case unsupported:
		return Diagnosis{UnsupportedRegistryState}, nil
	case unresolved:
		return Diagnosis{UnresolvedOperation}, nil
	default:
		return Diagnosis{StoredLinksObserved}, nil
	}
}

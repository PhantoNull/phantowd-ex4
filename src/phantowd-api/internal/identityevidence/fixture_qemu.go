//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// RunQEMUFixture compares public invented documents in memory only. It neither
// constructs a live Owner nor observes or invokes a Unix/Samba backend.
func RunQEMUFixture() error {
	r, err := serviceaccounts.New(20000, 20100)
	if err != nil {
		return ErrInvalid
	}
	r, err = r.Create(1, "fixture-user", "fixtureuser", serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
	if err != nil {
		return ErrInvalid
	}
	n := identityprovision.Journal{Format: identityprovision.Format, SchemaVersion: 1, Revision: 5, RegistryRevision: 2, Account: r.Accounts[0], Phase: identityprovision.UnixConfirmed}
	s := smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 5, NativeRevision: 5, Account: r.Accounts[0], SID: "S-1-5-21-1-2-3-4", Phase: smbprovision.CredentialSetDisabled}
	encode := func(v any) policyevidence.Slot {
		b, e := json.Marshal(v)
		if e != nil {
			return policyevidence.Slot{}
		}
		return policyevidence.Slot{State: policyevidence.Present, Data: b}
	}
	registry := encode(r)
	base := Entry{AccountID: "fixture-user", Native: encode(n), Samba: encode(s)}
	original := bytes.Clone(registry.Data)
	for _, scenario := range []string{"stable", "missing-registry", "missing-native", "native-intent", "enrollment-intent", "orphan", "tuple", "malformed-later"} {
		current := registry
		entries := []Entry{base}
		want := StoredLinksObserved
		malformed := false
		switch scenario {
		case "missing-registry":
			current = policyevidence.Slot{State: policyevidence.Absent}
			entries = []Entry{}
			want = NoRecordedRegistry
		case "missing-native":
			entries[0].Native = policyevidence.Slot{State: policyevidence.Absent}
			want = IncompleteDocuments
		case "native-intent":
			j := n
			j.Phase = identityprovision.UserIntent
			j.Revision = 4
			entries[0].Native = encode(j)
			entries[0].Samba = policyevidence.Slot{State: policyevidence.Absent}
			want = UnresolvedOperation
		case "enrollment-intent":
			j := s
			j.Phase = smbprovision.EnableIntent
			j.Revision = 6
			entries[0].Samba = encode(j)
			want = UnresolvedOperation
		case "orphan":
			current = policyevidence.Slot{State: policyevidence.Absent}
			want = InconsistentDocuments
		case "tuple":
			current = policyevidence.Slot{}
			j := s
			j.Account.Name = "different"
			entries[0].Samba = encode(j)
			want = InconsistentDocuments
		case "malformed-later":
			current = policyevidence.Slot{}
			entries[0].Samba = policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}
			malformed = true
		}
		before := make([]Entry, len(entries))
		copy(before, entries)
		for i := range before {
			before[i].Native.Data = bytes.Clone(entries[i].Native.Data)
			before[i].Samba.Data = bytes.Clone(entries[i].Samba.Data)
		}
		d, err := Match(current, entries)
		if malformed {
			if err != ErrInvalid || d != (Diagnosis{}) {
				return ErrInvalid
			}
		} else if err != nil || d.Kind() != want {
			return ErrInvalid
		}
		if !reflect.DeepEqual(before, entries) || !bytes.Equal(original, registry.Data) {
			return ErrInvalid
		}
		data, e := d.MarshalJSON()
		if e != ErrInvalid || len(data) != 0 {
			return ErrInvalid
		}
	}
	fmt.Println("PHANTOWD_IDENTITY_DOCUMENT_READY cases=8 complete_links=true malformed_not_hidden=true values_redacted=true readonly=true recovery=false admission=false scope=synthetic-memory-only")
	return nil
}

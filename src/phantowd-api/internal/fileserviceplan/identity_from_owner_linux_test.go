//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func ownerEvidenceFixture(t *testing.T) identityowner.FileServiceSnapshot {
	t.Helper()
	registry, err := serviceaccounts.New(1200, 1201)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = registry.Create(registry.Revision, "writer", "alice", serviceaccounts.Reservations{
		UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	account := registry.Accounts[0]
	return identityowner.FileServiceSnapshot{
		Registry: registry,
		Native: []identityprovision.Journal{{
			Format: identityprovision.Format, SchemaVersion: 1, Revision: 5,
			RegistryRevision: registry.Revision, Account: account, Phase: identityprovision.UnixConfirmed,
		}},
		UIDs: []uint32{account.UID}, GIDs: []uint32{account.GID}, Names: []string{account.Name},
		Samba:       []identityowner.FileServiceSamba{},
		Passdb:      []identityowner.FileServicePassdb{{AccountID: account.ID}},
		Fingerprint: [32]byte{1},
	}
}

func TestIdentityFromOwnerEvidenceCopiesFreshCompleteState(t *testing.T) {
	evidence := ownerEvidenceFixture(t)
	got, err := identityFromOwnerEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete || got.Generation != evidence.Registry.Revision || got.Fingerprint != evidence.Fingerprint ||
		len(got.Registry.Accounts) != 1 || got.Registry.Accounts[0].ID != "writer" ||
		len(got.UnixUIDs) != 1 || got.UnixUIDs[0] != evidence.UIDs[0] ||
		got.UnixGIDs[0] != evidence.GIDs[0] || got.Samba == nil || len(got.Samba) != 0 || got.KerberosReady {
		t.Fatalf("Owner evidence was not faithfully adapted: %+v", got)
	}
	got.Registry.Accounts[0].Name = "mutated"
	got.UnixUIDs[0]++
	if evidence.Registry.Accounts[0].Name != "alice" || evidence.UIDs[0] == got.UnixUIDs[0] {
		t.Fatal("planner snapshot aliases Owner evidence slices")
	}
}

func TestIdentityFromOwnerEvidenceRejectsIncompleteOrMisalignedSources(t *testing.T) {
	for name, mutate := range map[string]func(*identityowner.FileServiceSnapshot){
		"zero fingerprint":         func(e *identityowner.FileServiceSnapshot) { e.Fingerprint = [32]byte{} },
		"missing native journal":   func(e *identityowner.FileServiceSnapshot) { e.Native = nil },
		"missing passdb result":    func(e *identityowner.FileServiceSnapshot) { e.Passdb = nil },
		"wrong account binding":    func(e *identityowner.FileServiceSnapshot) { e.Passdb[0].AccountID = "other" },
		"malformed native journal": func(e *identityowner.FileServiceSnapshot) { e.Native[0].Phase = identityprovision.Reserved },
	} {
		t.Run(name, func(t *testing.T) {
			evidence := ownerEvidenceFixture(t)
			mutate(&evidence)
			if _, err := identityFromOwnerEvidence(evidence); err == nil {
				t.Fatal("invalid Owner evidence was accepted")
			}
		})
	}
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

func TestEnrollmentLookupRendersConfirmedDisabledPrivateIdentity(t *testing.T) {
	service := ownerEvidenceFixture(t)
	evidence := identityowner.NativeLookupSnapshot{Registry: service.Registry, Native: service.Native,
		Samba: []smbprovision.Journal{}, UIDs: service.UIDs, GIDs: service.GIDs, Names: service.Names, Fingerprint: [32]byte{2}}
	lookup, err := sambaEnrollmentFromEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil || lookup.Fingerprint() != evidence.Fingerprint || nss != sambaFilesOnlyNSS ||
		!strings.Contains(passwd, "alice:!:1200:1200::/:/sbin/nologin\n") || !strings.Contains(group, "alice:!:1200:\n") {
		t.Fatal("disabled-first enrollment needs locked files-only private identities:", err)
	}
	parsed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal(err)
	}
	if status, err := parsed.Assess(evidence.Registry.Accounts[0]); err != nil || status != unixidentity.Observed {
		t.Fatal("lookup documents do not resolve the native private identity:", err)
	}
	if len(passwd)+len(group)+len(nss) > MaxSambaNSSBytes {
		t.Fatal("enrollment lookup exceeded its bounded document budget")
	}
	evidence.Registry.Accounts[0].Name = "changed-copy"
	after, _, _, err := lookup.LookupDocuments()
	if err != nil || after != passwd {
		t.Fatal("enrollment lookup aliases supplied evidence:", err)
	}
	if _, err := json.Marshal(lookup); err == nil {
		t.Fatal("private NSS documents must not cross JSON seams")
	}
}

func TestEnrollmentLookupRefusesIncompleteEvidenceAndZeroValues(t *testing.T) {
	for name, mutate := range map[string]func(*identityowner.NativeLookupSnapshot){
		"zero fingerprint": func(e *identityowner.NativeLookupSnapshot) { e.Fingerprint = [32]byte{} },
		"missing native":   func(e *identityowner.NativeLookupSnapshot) { e.Native = nil },
		"unknown journals": func(e *identityowner.NativeLookupSnapshot) { e.Samba = nil },
		"missing census":   func(e *identityowner.NativeLookupSnapshot) { e.Names = nil },
		"missing UID":      func(e *identityowner.NativeLookupSnapshot) { e.UIDs = []uint32{} },
		"missing GID":      func(e *identityowner.NativeLookupSnapshot) { e.GIDs = []uint32{} },
		"missing name":     func(e *identityowner.NativeLookupSnapshot) { e.Names = []string{} },
		"retired":          func(e *identityowner.NativeLookupSnapshot) { e.Registry.Accounts[0].State = serviceaccounts.Retired },
		"wrong native":     func(e *identityowner.NativeLookupSnapshot) { e.Native[0].Account.Name = "other" },
		"uncertain Samba": func(e *identityowner.NativeLookupSnapshot) {
			e.Samba = []smbprovision.Journal{{Format: smbprovision.Format, SchemaVersion: 1, Revision: 2,
				NativeRevision: 5, Account: e.Native[0].Account, Phase: smbprovision.CreateIntent}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := ownerEvidenceFixture(t)
			e := identityowner.NativeLookupSnapshot{Registry: service.Registry, Native: service.Native,
				Samba: []smbprovision.Journal{}, UIDs: service.UIDs, GIDs: service.GIDs, Names: service.Names, Fingerprint: [32]byte{2}}
			mutate(&e)
			lookup, err := sambaEnrollmentFromEvidence(e)
			if err == nil || lookup != (SambaEnrollmentLookup{}) {
				t.Fatal("invalid evidence returned an enrollment lookup")
			}
		})
	}
	for _, lookup := range []SambaEnrollmentLookup{{}} {
		p, g, n, err := lookup.LookupDocuments()
		if !errors.Is(err, ErrNotReady) || p != "" || g != "" || n != "" || lookup.Fingerprint() != [32]byte{} {
			t.Fatal("zero lookup returned usable documents")
		}
	}
	if _, err := SambaEnrollmentLookupFromOwner(context.Background(), nil); !errors.Is(err, ErrNotReady) {
		t.Fatal("nil Owner accepted")
	}
	var decoded SambaEnrollmentLookup
	if json.Unmarshal([]byte(`{}`), &decoded) == nil {
		t.Fatal("enrollment lookup must not be accepted from JSON")
	}
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func encoded(t *testing.T, v any) policyevidence.Slot {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return policyevidence.Slot{State: policyevidence.Present, Data: b}
}
func fixture(t *testing.T) (serviceaccounts.Registry, []identityprovision.Journal, []smbprovision.Journal) {
	t.Helper()
	r, err := serviceaccounts.New(20000, 20200)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		r, err = r.Create(r.Revision, id, id, serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
		if err != nil {
			t.Fatal(err)
		}
	}
	n := make([]identityprovision.Journal, 2)
	s := make([]smbprovision.Journal, 2)
	for i, a := range r.Accounts {
		n[i] = identityprovision.Journal{Format: identityprovision.Format, SchemaVersion: 1, Revision: 5, RegistryRevision: uint64(i) + 2, Account: a, Phase: identityprovision.UnixConfirmed}
		s[i] = smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 5, NativeRevision: 5, Account: a, SID: fmt.Sprintf("S-1-5-21-1-2-3-%d", i+1), Phase: smbprovision.CredentialSetDisabled}
	}
	return r, n, s
}
func records(t *testing.T, n []identityprovision.Journal, s []smbprovision.Journal) []Entry {
	t.Helper()
	out := make([]Entry, len(n))
	for i := range n {
		out[i] = Entry{AccountID: n[i].Account.ID, Native: encoded(t, n[i]), Samba: encoded(t, s[i])}
	}
	return out
}
func want(t *testing.T, r policyevidence.Slot, e []Entry, k Kind) {
	t.Helper()
	d, err := Match(r, e)
	if err != nil || d.Kind() != k {
		t.Fatalf("kind=%s error=%v want=%s", d.Kind(), err, k)
	}
}

func TestCompleteStoredLinksAndNoInputMutation(t *testing.T) {
	r, n, s := fixture(t)
	e := records(t, n, s)
	wire := encoded(t, r)
	saved := make([]Entry, len(e))
	copy(saved, e)
	for i := range saved {
		saved[i].Native.Data = bytes.Clone(e[i].Native.Data)
		saved[i].Samba.Data = bytes.Clone(e[i].Samba.Data)
	}
	original := bytes.Clone(wire.Data)
	want(t, wire, e, StoredLinksObserved)
	e[0], e[1] = e[1], e[0]
	want(t, wire, e, StoredLinksObserved)
	e[0], e[1] = e[1], e[0]
	if !reflect.DeepEqual(saved, e) || !bytes.Equal(original, wire.Data) {
		t.Fatal("input modified")
	}
	e[0].Samba = policyevidence.Slot{State: policyevidence.Absent}
	want(t, wire, e, StoredLinksObserved)
	r.Accounts[0].State = serviceaccounts.Enabled
	want(t, encoded(t, r), e, StoredLinksObserved)
}
func TestMissingUnavailableOrphanAndUnsupported(t *testing.T) {
	r, n, s := fixture(t)
	empty := []Entry{}
	absent := policyevidence.Slot{State: policyevidence.Absent}
	want(t, absent, empty, NoRecordedRegistry)
	want(t, policyevidence.Slot{}, empty, IncompleteDocuments)
	want(t, absent, records(t, n, s), InconsistentDocuments)
	want(t, encoded(t, r), empty, IncompleteDocuments)
	e := records(t, n, s)
	e[0].Native = absent
	want(t, encoded(t, r), e, IncompleteDocuments)
	e = records(t, n, s)
	e[0].Samba = policyevidence.Slot{}
	want(t, encoded(t, r), e, IncompleteDocuments)
	e = records(t, n, s)
	e[0].AccountID = "foreign"
	want(t, encoded(t, r), e, InconsistentDocuments)
	e = records(t, n, s)
	e = append(e, e[0])
	want(t, encoded(t, r), e, InconsistentDocuments)
	r.Accounts[0].State = serviceaccounts.Retired
	want(t, encoded(t, r), records(t, n, s), UnsupportedRegistryState)
	r, _ = serviceaccounts.New(20000, 20200)
	want(t, encoded(t, r), empty, StoredLinksObserved)
}
func TestNativeAndEnrollmentLinksAndUncertainPhases(t *testing.T) {
	for _, change := range []string{"uid", "name", "creation", "order", "native-revision", "sid", "partial-with-enrollment", "two-partial", "stale-partial"} {
		t.Run(change, func(t *testing.T) {
			r, n, s := fixture(t)
			switch change {
			case "uid":
				n[0].Account.UID++
				n[0].Account.GID++
			case "name":
				n[0].Account.Name = "other"
			case "creation":
				n[0].RegistryRevision = 4
			case "order":
				n[1].RegistryRevision = n[0].RegistryRevision
			case "native-revision":
				s[0].NativeRevision = 4
			case "sid":
				s[1].SID = s[0].SID
			case "partial-with-enrollment":
				n[1].Phase = identityprovision.UserIntent
				n[1].Revision = 4
			case "two-partial":
				for i := range n {
					n[i].Phase = identityprovision.UserIntent
					n[i].Revision = 4
					n[i].RegistryRevision = r.Revision
				}
			case "stale-partial":
				n[0].Phase = identityprovision.Reserved
				n[0].Revision = 1
			}
			want(t, encoded(t, r), records(t, n, s), InconsistentDocuments)
		})
	}
	r, n, s := fixture(t)
	n[1].Phase = identityprovision.UserIntent
	n[1].Revision = 4
	e := records(t, n, s)
	e[1].Samba = policyevidence.Slot{State: policyevidence.Absent}
	want(t, encoded(t, r), e, UnresolvedOperation)
	for _, phase := range []struct {
		name     string
		revision uint64
	}{{smbprovision.CreateIntent, 2}, {smbprovision.PasswordIntent, 4}, {smbprovision.EnableIntent, 6}, {smbprovision.DisableIntent, 8}, {smbprovision.ReviewRequired, 10}} {
		r, n, s = fixture(t)
		s[0].Phase = phase.name
		s[0].Revision = phase.revision
		if phase.revision == 2 {
			s[0].SID = ""
		}
		want(t, encoded(t, r), records(t, n, s), UnresolvedOperation)
	}
}
func TestMalformedLaterDocumentNeverHiddenByMissingOrMismatch(t *testing.T) {
	r, n, s := fixture(t)
	for _, registry := range []policyevidence.Slot{encoded(t, r), {State: policyevidence.Absent}, {State: policyevidence.Unavailable}} {
		e := records(t, n, s)
		e[0].AccountID = "foreign"
		e[1].Samba = policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}
		if d, err := Match(registry, e); err != ErrInvalid || d != (Diagnosis{}) {
			t.Fatal("invalid present evidence hidden")
		}
	}
	for _, slot := range []policyevidence.Slot{{State: 255}, {State: policyevidence.Absent, Data: []byte("x")}, {State: policyevidence.Present}, {State: policyevidence.Present, Data: []byte(`{"format":null}`)}} {
		if d, err := Match(slot, []Entry{}); err != ErrInvalid || d != (Diagnosis{}) {
			t.Fatal("invalid role accepted")
		}
	}
	if d, err := Match(encoded(t, r), nil); err != ErrInvalid || d != (Diagnosis{}) {
		t.Fatal("unknown roster treated complete")
	}
}

func TestKnownIdentityMismatchPrecedesUnavailableDocuments(t *testing.T) {
	r, n, s := fixture(t)
	s[0].Account.Name = "different"
	e := records(t, n, s)
	want(t, policyevidence.Slot{}, e, InconsistentDocuments)
	e[0].Native = policyevidence.Slot{}
	want(t, encoded(t, r), e, InconsistentDocuments)
}

func TestExactAggregateBoundaryAndOverflow(t *testing.T) {
	_, n, s := fixture(t)
	base := records(t, n, s)[0]
	pad := func(wire []byte) []byte {
		return append(bytes.Clone(wire), bytes.Repeat([]byte{' '}, 4096-len(wire))...)
	}
	base.Native.Data, base.Samba.Data = pad(base.Native.Data), pad(base.Samba.Data)
	entries := make([]Entry, 512)
	total := 0
	for i := range entries {
		entries[i] = base
		total += len(base.AccountID) + len(base.Native.Data) + len(base.Samba.Data)
	}
	excess := total - MaxInputBytes
	entries[511].Samba.Data = entries[511].Samba.Data[:4096-excess]
	// Repeated names are deliberately inconsistent; inclusive wire admission is
	// tested separately from claiming a valid/complete 512-account generation.
	want(t, policyevidence.Slot{}, entries, InconsistentDocuments)
	entries[511].Samba.Data = append(bytes.Clone(entries[511].Samba.Data), ' ')
	if d, err := Match(policyevidence.Slot{}, entries); err != ErrInvalid || d != (Diagnosis{}) {
		t.Fatal("aggregate limit lost")
	}
}
func TestBoundsAndPrivateConcurrentDiagnosis(t *testing.T) {
	r, n, s := fixture(t)
	e := records(t, n, s)
	wire := encoded(t, r)
	padded := bytes.Clone(e[0].Native.Data)
	padded = append(padded, bytes.Repeat([]byte{' '}, identityprovision.MaxBytes-len(padded))...)
	e[0].Native.Data = padded
	want(t, wire, e, StoredLinksObserved)
	e[0].Native.Data = append(padded, ' ')
	if d, err := Match(wire, e); err != ErrInvalid || d != (Diagnosis{}) {
		t.Fatal("document bound lost")
	}
	if d, err := Match(wire, make([]Entry, serviceaccounts.MaxRecords+1)); err != ErrInvalid || d != (Diagnosis{}) {
		t.Fatal("count bound lost")
	}
	e = records(t, n, s)
	d, err := Match(wire, e)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{d, &d, e[0], &e[0]} {
		b, err := json.Marshal(v)
		if !errors.Is(err, ErrInvalid) || len(b) != 0 {
			t.Fatal("generic JSON admitted")
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", v, v), "first") {
			t.Fatal("identity formatted")
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &d); !errors.Is(err, ErrInvalid) {
		t.Fatal("decode admitted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				got, err := Match(wire, e)
				if err != nil || !reflect.DeepEqual(got, d) {
					t.Error("concurrent diagnosis")
				}
			}
		})
	}
	wg.Wait()
}

func TestExactMaximumRegistryRevision(t *testing.T) {
	r, n, s := fixture(t)
	r.Revision = math.MaxUint64
	n[1].RegistryRevision = math.MaxUint64
	want(t, encoded(t, r), records(t, n, s), StoredLinksObserved)
}

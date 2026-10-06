//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func TestNativeLookupPrecedesSambaEnrollmentWithoutGrantingServiceEvidence(t *testing.T) {
	owner, local, _ := fixture(t)
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	beforeRegistry, beforeNative, err := owner.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(lookup.Registry, beforeRegistry) || !reflect.DeepEqual(lookup.Native, beforeNative) ||
		len(lookup.Samba) != 0 || lookup.Fingerprint == [32]byte{} || len(lookup.UIDs) != 2 || len(lookup.GIDs) != 2 {
		t.Fatal("confirmed disabled identities need a native-only lookup without a Samba backend:", err)
	}
	if _, err := owner.FileServiceSnapshot(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("native lookup must not manufacture credential/service evidence:", err)
	}
	if _, err := json.Marshal(lookup); err == nil {
		t.Fatal("native lookup must not be serializable")
	}
	var decoded NativeLookupSnapshot
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil {
		t.Fatal("native lookup must not be deserializable")
	}
	afterRegistry, afterNative, err := owner.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(beforeRegistry, afterRegistry) || !reflect.DeepEqual(beforeNative, afterNative) || local.calls != 2 {
		t.Fatal("native lookup must not mutate identity state:", err)
	}
}

func TestNativeLookupRefusesIncompleteAndChangedIdentities(t *testing.T) {
	owner, local, _ := fixture(t)
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []uint64{0, 1} {
		if revision != 0 {
			if err := owner.Operation(account.ID).Step(ctx, revision); err != nil {
				t.Fatal(err)
			}
		}
		got, err := owner.NativeLookupSnapshot(ctx)
		if !errors.Is(err, ErrPending) || !reflect.DeepEqual(got, NativeLookupSnapshot{}) {
			t.Fatal("incomplete identity must refuse the entire native lookup:", err)
		}
	}
	if err := owner.Operation(account.ID).Step(ctx, 3); err != nil {
		t.Fatal(err)
	}
	before, err := owner.NativeLookupSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := account
	changed.UID++
	local.users[account.ID] = changed
	got, err := owner.NativeLookupSnapshot(ctx)
	if !errors.Is(err, ErrReview) || !reflect.DeepEqual(got, NativeLookupSnapshot{}) {
		t.Fatal("current Unix drift must refuse lookup:", err)
	}
	local.users[account.ID] = account
	after, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || local.calls != 2 {
		t.Fatal("refused read must not change durable state or invoke native commands:", err)
	}
}

func TestNativeLookupHasIndependentFreshnessAndNoCredentialObserver(t *testing.T) {
	backend := &modeledSMB{}
	owner, local, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	before, err := owner.NativeLookupSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	service, err := owner.FileServiceSnapshot(ctx)
	if err != nil || service.Fingerprint == before.Fingerprint {
		t.Fatal("lookup and service evidence require distinct fingerprint domains:", err)
	}
	reads := backend.observeSetCalls + backend.observeCalls
	backend.observeErr = true
	before.Registry.Accounts[0].Name = "caller-copy"
	before.Native[0].Account.Name = "caller-copy"
	before.UIDs[0]++
	after, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || after.Registry.Accounts[0] != account || after.Native[0].Account != account || after.Fingerprint != before.Fingerprint {
		t.Fatal("native lookup must be independent of passdb reads and returned mutable slices:", err)
	}
	if backend.observeSetCalls+backend.observeCalls != reads {
		t.Fatal("native lookup queried credential state")
	}
	if err := owner.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal(err)
	}
	changed, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || changed.Fingerprint == after.Fingerprint || changed.Native[0] != after.Native[0] {
		t.Fatal("desired state must invalidate lookup without rewriting its native journal:", err)
	}
	foreign := serviceaccounts.Account{ID: "foreign", Name: "foreignuser", UID: 22000, GID: 22000}
	local.users[foreign.ID], local.groups[foreign.ID] = foreign, foreign
	withForeign, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || withForeign.Fingerprint == changed.Fingerprint || len(withForeign.Registry.Accounts) != 1 {
		t.Fatal("complete census changes invalidate lookup but never adopt a foreign identity:", err)
	}
	backend.observeErr = false
	if err := owner.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	reads = backend.observeSetCalls + backend.observeCalls
	backend.observeErr = true
	withJournal, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || withJournal.Fingerprint == withForeign.Fingerprint || len(withJournal.Samba) != 1 ||
		withJournal.Native[0] != withForeign.Native[0] || backend.observeSetCalls+backend.observeCalls != reads {
		t.Fatal("stable enrollment journals must bind lookup freshness without a live credential read:", err)
	}
	withJournal.Samba[0].Account.Name = "caller-copy"
	fresh, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || fresh.Samba[0].Account != account || fresh.Fingerprint != withJournal.Fingerprint {
		t.Fatal("returned Samba journal aliases the Owner store:", err)
	}
}

func TestNativeLookupAdmissionAndLockedDerivation(t *testing.T) {
	owner, _, _ := fixture(t)
	ctx := context.Background()
	if err := owner.WithNativeLookupSnapshot(ctx, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil callback must refuse:", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, input := range []context.Context{nil, cancelled} {
		got, err := owner.NativeLookupSnapshot(input)
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, NativeLookupSnapshot{}) {
			t.Fatal("invalid admission must return no evidence:", err)
		}
	}
	called := false
	err := owner.WithNativeLookupSnapshot(ctx, func(snapshot NativeLookupSnapshot) error {
		called = true
		if snapshot.Registry.Validate() != nil || snapshot.Fingerprint == [32]byte{} || snapshot.Native == nil || snapshot.Samba == nil {
			return errors.New("empty ledger lacks complete native observation")
		}
		if _, err := owner.NativeLookupSnapshot(ctx); !errors.Is(err, ErrBusy) {
			return errors.New("native lookup bypassed the Owner lock")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatal("bounded native derivation must retain the mutation lock:", err)
	}
	during, cancelDuring := context.WithCancel(ctx)
	if err := owner.WithNativeLookupSnapshot(during, func(NativeLookupSnapshot) error { cancelDuring(); return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancellation during derivation must refuse success:", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := owner.NativeLookupSnapshot(ctx); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, NativeLookupSnapshot{}) {
		t.Fatal("closed Owner must provide no lookup:", err)
	}
}

func TestFileServiceSnapshotRefusesLaterNativeDriftAtomically(t *testing.T) {
	backend := &modeledSMB{}
	owner, local, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	first, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, first.ID)
	second, err := owner.Reserve(ctx, 2, "second", "seconduser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, second.ID)
	before, err := owner.FileServiceSnapshot(ctx)
	if err != nil || len(before.Native) != 2 {
		t.Fatal("confirmed disabled native identities must be observable with an absent-passdb backend:", err)
	}
	reads := backend.observeSetCalls
	changed := second
	changed.GID++
	local.users[second.ID] = changed
	refused, err := owner.FileServiceSnapshot(ctx)
	if !errors.Is(err, ErrReview) || !reflect.DeepEqual(refused, FileServiceSnapshot{}) {
		t.Fatal("a later conflicting Unix identity must refuse the whole evidence bundle:", err)
	}
	if backend.observeSetCalls != reads {
		t.Fatal("native drift must be refused before passdb observation")
	}
	local.users[second.ID] = second
	after, err := owner.FileServiceSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only refusal must leave ledger and journals unchanged:", err)
	}
	if local.calls != 4 || backend.createCalls != 0 || backend.setCalls != 0 || backend.enableCalls != 0 || backend.disableCalls != 0 {
		t.Fatal("evidence collection caused a native or Samba mutation")
	}
}

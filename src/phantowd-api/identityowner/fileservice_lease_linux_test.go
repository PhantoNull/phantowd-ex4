// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

func TestFileServiceLeaseRetainsExactOwnerUntilRelease(t *testing.T) {
	backend := &closeCountingSMB{}
	owner, model, directory := fixtureWithSMB(t, backend)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal("retain exact complete identity evidence:", err)
	}
	t.Cleanup(func() { lease.Release() })
	if err := lease.Verify(ctx); err != nil {
		t.Fatal("unchanged identity lease:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) || backend.closeCalls != 0 {
		t.Fatal("consumer did not retain backend/store authority:", err, backend.closeCalls)
	}
	if competing, err := open(directory, model.dependencies()); !errors.Is(err, ErrBusy) || competing != nil {
		t.Fatal("consumer allowed a competing owner after busy close:", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal("release stopped consumer:", err)
	}
	if err := owner.Close(); err != nil || backend.closeCalls != 1 {
		t.Fatal("last release did not permit exact backend close:", err, backend.closeCalls)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("released consumer verified:", err)
	}
}

func TestFileServiceLeaseCannotCrossSerializationBoundary(t *testing.T) {
	owner, _, _ := fixture(t)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	if _, err := json.Marshal(lease); err == nil {
		t.Fatal("retained identity authority is serializable")
	}
	if err := json.Unmarshal([]byte(`{}`), lease); err == nil {
		t.Fatal("serialized input can address a live identity lease")
	}
	if err := lease.Verify(ctx); err != nil {
		t.Fatal("rejected input changed live lease:", err)
	}
}

func TestFileServiceLeaseObservedDriftNeverRevives(t *testing.T) {
	owner, model, _ := fixture(t)
	ctx := context.Background()
	before, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, before.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	foreign := serviceaccounts.Account{ID: "foreign", Name: "foreignuser", UID: 22000, GID: 22000}
	model.users[foreign.ID], model.groups[foreign.ID] = foreign, foreign
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("changed complete local census did not invalidate consumer:", err)
	}
	delete(model.users, foreign.ID)
	delete(model.groups, foreign.ID)
	restored, err := owner.FileServiceSnapshot(ctx)
	if err != nil || restored.Fingerprint != before.Fingerprint {
		t.Fatal("control did not restore exactly matching identity evidence:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("restored evidence revived an invalid consumer:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("review dropped lifetime retention:", err)
	}
}

func TestFileServiceLeaseCapacityRefusesWithoutEffectsAndReusesReleasedSlot(t *testing.T) {
	owner, _, _ := fixture(t)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	leases := []*FileServiceLease{}
	t.Cleanup(func() {
		for _, lease := range leases {
			lease.Release()
		}
	})
	for range 16 {
		lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
		if err != nil {
			t.Fatal("bounded consumer control refused:", err)
		}
		leases = append(leases, lease)
	}
	extra, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if extra != nil {
		leases = append(leases, extra)
	}
	if !errors.Is(err, ErrBusy) || extra != nil {
		t.Fatal("consumer capacity did not fail atomically:", err)
	}
	copyOfFirst := *leases[0]
	if err := copyOfFirst.Release(); err != nil {
		t.Fatal(err)
	}
	if err := leases[0].Release(); err != nil {
		t.Fatal("copy release was not idempotent:", err)
	}
	replacement, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal("released bounded slot was not reusable:", err)
	}
	leases = append(leases, replacement)
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("copied/repeated release dropped other consumers:", err)
	}
}

func fileServiceSMBLeaseFixture(t *testing.T) (*Owner, *modeledSMB, serviceaccounts.Account) {
	t.Helper()
	backend := &modeledSMB{}
	owner, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	if err := owner.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal(err)
	}
	smb := owner.SMB(account.ID)
	for _, step := range []func() error{
		func() error { return smb.Begin(ctx, 5) },
		func() error { return smb.Step(ctx, 1) },
		func() error { return smb.SetPasswordDisabled(ctx, 3, []byte("fixture-only-secret")) },
		func() error { return smb.Enable(ctx, 5) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return owner, backend, account
}

func TestFileServiceLeaseDoesNotBlockSMBRevocationOrCredentialRotation(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	smb := owner.SMB(account.ID)
	if err := smb.Disable(ctx, 7); err != nil || backend.disableCalls != 1 || !backend.observation.Disabled {
		t.Fatal("consumer blocked explicit revocation:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("revocation did not invalidate old identity evidence:", err)
	}
	if err := smb.SetPasswordDisabled(ctx, 9, []byte("rotated-fixture-only-secret")); err != nil || backend.setCalls != 2 {
		t.Fatal("review consumer blocked disabled credential rotation:", err)
	}
	if err := smb.Enable(ctx, 11); err != nil || backend.observation.Disabled {
		t.Fatal("retained review froze explicit account operations:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("credential/account restoration revived old consumer:", err)
	}
}

func TestFileServiceLeaseObservationFailureStaysReviewAndRetained(t *testing.T) {
	owner, backend, _ := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	backend.observeErr = true
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain passdb observation did not retain review:", err)
	}
	backend.observeErr = false
	restored, err := owner.FileServiceSnapshot(ctx)
	if err != nil || restored.Fingerprint != snapshot.Fingerprint {
		t.Fatal("failure control did not restore exact evidence:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("restored observation revived uncertain consumer:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("uncertain observation dropped authority:", err)
	}
}

func TestFileServiceLeaseAdmissionRefusalsHaveNoEffects(t *testing.T) {
	owner, _, _ := fixtureWithSMB(t, &modeledSMB{})
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if extra, err := owner.RetainFileServiceSnapshot(canceled, snapshot.Fingerprint); extra != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled admission created a consumer:", err)
	}
	if err := lease.Verify(canceled); !errors.Is(err, ErrUnavailable) {
		t.Fatal("pre-admission cancellation did not refuse verification:", err)
	}
	owner.mu.Lock()
	busy := lease.Verify(ctx)
	extra, acquireErr := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	owner.mu.Unlock()
	if !errors.Is(busy, ErrBusy) || !errors.Is(acquireErr, ErrBusy) || extra != nil {
		t.Fatal("busy operation created effects:", busy, acquireErr)
	}
	if err := lease.Verify(ctx); err != nil {
		t.Fatal("pre-admission cancellation/busy invalidated evidence:", err)
	}
	if err := owner.SetDesiredState(ctx, snapshot.Registry.Revision, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("consumer froze desired-state operations:", err)
	}
	if extra, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint); extra != nil || !errors.Is(err, ErrConflict) {
		t.Fatal("stale candidate retained different evidence:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("desired-state change did not invalidate original consumer:", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("refused admissions leaked a consumer:", err)
	}
}

func TestFileServiceLeaseCancellationDuringObservationRetainsReview(t *testing.T) {
	owner, _, _ := fixture(t)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Release() })
	observe := owner.deps.observe
	canceled, cancel := context.WithCancel(ctx)
	defer cancel()
	owner.deps.observe = func(ctx context.Context) (unixidentity.Snapshot, error) {
		cancel()
		return observe(ctx)
	}
	if err := lease.Verify(canceled); !errors.Is(err, ErrReview) {
		t.Fatal("cancellation during an admitted observation did not retain review:", err)
	}
	owner.deps.observe = observe
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("fresh context revived uncertain consumer:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("admitted cancellation released authority:", err)
	}
}

func TestFileServiceLeaseConcurrentCopiesReleaseOnlyOneReference(t *testing.T) {
	backend := &closeCountingSMB{}
	owner, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	snapshot, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.RetainFileServiceSnapshot(ctx, snapshot.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Release(); second.Release() })
	var workers sync.WaitGroup
	for range 32 {
		copyOfFirst := *first
		workers.Go(func() {
			if err := copyOfFirst.Release(); err != nil {
				t.Error(err)
			}
			if err := first.Verify(ctx); !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrBusy) {
				t.Error("concurrently released lease verified:", err)
			}
		})
	}
	workers.Wait()
	if err := second.Verify(ctx); err != nil {
		t.Fatal("copied releases dropped independent consumer:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) || backend.closeCalls != 0 {
		t.Fatal("concurrent release dropped retained backend:", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil || backend.closeCalls != 1 {
		t.Fatal("last independent release did not drain authority:", err)
	}
}

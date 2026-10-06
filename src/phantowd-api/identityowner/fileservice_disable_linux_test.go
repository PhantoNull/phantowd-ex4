// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func TestSMBFileServiceDisableHandsOffWithoutReleasingAuthority(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	before, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.RetainSMBFileServiceSnapshot(ctx, before.Fingerprint, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Release() })
	copyOfOld := *old
	successor, err := owner.SMB(account.ID).DisableForFileService(ctx, 7, old)
	if err != nil || successor == nil {
		t.Fatal("verified revocation did not transfer authority:", err)
	}
	t.Cleanup(func() { successor.Release() })
	if err := old.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("old token survived authorized mutation:", err)
	}
	if err := successor.Verify(ctx); err != nil {
		t.Fatal("successor cannot verify complete post-revocation evidence:", err)
	}
	journal, err := owner.SMB(account.ID).Load(ctx)
	if err != nil || journal.Phase != smbprovision.Disabled || journal.Revision != 9 ||
		journal.SID != before.Samba[0].Journal.SID {
		t.Fatal("revocation changed account identity or lacked confirmation:", err)
	}
	if err := copyOfOld.Release(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("old-token release dropped successor retention:", err)
	}
	if err := successor.Verify(ctx); err != nil {
		t.Fatal("old-token release invalidated successor:", err)
	}
	if err := successor.Release(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("successor release did not drain the exact Owner:", err)
	}
}

func TestSMBFileServiceDisableUncertaintyRetainsReviewWithoutRetry(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Release() })
	backend.disableErr = true
	op := owner.SMB(account.ID)
	if successor, err := op.DisableForFileService(ctx, 7, old); successor != nil || !errors.Is(err, ErrReview) {
		t.Fatal("uncertain revocation yielded successor authority:", err)
	}
	journal, err := op.Load(ctx)
	if err != nil || journal.Phase != smbprovision.ReviewRequired {
		t.Fatal("uncertain revocation was not journaled as review:", err)
	}
	backend.disableErr = false
	if successor, err := op.DisableForFileService(ctx, journal.Revision, old); successor != nil || !errors.Is(err, ErrReview) {
		t.Fatal("repaired backend revived quarantined authority:", err)
	}
	if backend.disableCalls != 1 {
		t.Fatal("uncertain intent was replayed")
	}
	if err := old.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("old lease lost sticky review:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("uncertainty released the consumer reference:", err)
	}
}

func TestSMBFileServiceDisableRejectsOtherwiseValidUnixCensusDrift(t *testing.T) {
	backend := &modeledSMB{}
	owner, identities, account := fileServiceSMBLeaseFixtureWithBackend(t, backend)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Release() })
	backend.onDisable = func() {
		identities.users["external"] = serviceaccounts.Account{Name: "externaluser", UID: 25000, GID: 25000}
	}
	if successor, err := owner.SMB(account.ID).DisableForFileService(ctx, 7, old); successor != nil || !errors.Is(err, ErrReview) {
		t.Fatal("target confirmation concealed unrelated Unix census drift:", err)
	}
	journal, err := owner.SMB(account.ID).Load(ctx)
	if err != nil || journal.Phase != smbprovision.Disabled || journal.Revision != 9 {
		t.Fatal("completed revocation was erased or retried:", err)
	}
	delete(identities.users, "external")
	if err := old.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("restoring external census revived the old token:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("drift released service authority:", err)
	}
}

func TestSMBFileServiceDisablePreAdmissionRefusalsHaveNoMutation(t *testing.T) {
	for _, scenario := range []string{"nil-token", "foreign-owner", "unbound", "released", "canceled", "nil-context", "stale-revision", "unknown-account"} {
		t.Run(scenario, func(t *testing.T) {
			owner, backend, account := fileServiceSMBLeaseFixture(t)
			ctx := context.Background()
			evidence, err := owner.FileServiceSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { lease.Release() })
			candidate, op, operationContext, revision, want := lease, owner.SMB(account.ID), ctx, uint64(7), ErrConflict
			switch scenario {
			case "nil-token":
				candidate, want = nil, ErrInvalid
			case "foreign-owner":
				other, foreign, _ := fileServiceSMBLeaseFixture(t)
				candidate, err = other.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, foreign)
			case "unbound":
				candidate, err = owner.RetainFileServiceSnapshot(ctx, evidence.Fingerprint)
			case "released":
				err, want = candidate.Release(), ErrUnavailable
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				operationContext, want = canceled, ErrUnavailable
			case "nil-context":
				operationContext, want = nil, ErrUnavailable
			case "stale-revision":
				revision, want = 5, smbprovision.ErrConflict
			case "unknown-account":
				op, want = owner.SMB("absent"), smbprovision.ErrConflict
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { candidate.Release() })
			if successor, err := op.DisableForFileService(operationContext, revision, candidate); successor != nil || !errors.Is(err, want) {
				t.Fatal("pre-admission refusal accepted mutation:", err)
			}
			after, err := owner.FileServiceSnapshot(ctx)
			if err != nil || after.Fingerprint != evidence.Fingerprint || backend.disableCalls != 0 {
				t.Fatal("rejected request changed complete evidence:", err)
			}
			if scenario != "released" {
				if err := lease.Verify(ctx); err != nil {
					t.Fatal("pre-admission refusal poisoned unchanged authority:", err)
				}
			}
		})
	}
}

func TestSMBFileServiceDisableTransfersSlotAtCapacity(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var leases []*FileServiceLease
	t.Cleanup(func() {
		for _, lease := range leases {
			lease.Release()
		}
	})
	for range 16 {
		lease, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	successor, err := owner.SMB(account.ID).DisableForFileService(ctx, 7, leases[0])
	if err != nil || successor == nil {
		t.Fatal("full capacity blocked atomic replacement:", err)
	}
	leases = append(leases, successor)
	after, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if extra, err := owner.RetainSMBFileServiceSnapshot(ctx, after.Fingerprint, backend); extra != nil || !errors.Is(err, ErrBusy) {
		if extra != nil {
			leases = append(leases, extra)
		}
		t.Fatal("replacement freed or exceeded the bounded slot:", err)
	}
	if err := leases[0].Release(); err != nil {
		t.Fatal(err)
	}
	if err := successor.Verify(ctx); err != nil {
		t.Fatal("old release disturbed replacement:", err)
	}
	if err := leases[1].Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("other stale consumers were silently refreshed:", err)
	}
}

func TestSMBFileServiceDisableSerializesCloseAcrossTransfer(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Release() })
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(proceed) })
	backend.onDisable = func() { close(entered); <-proceed }
	type outcome struct {
		lease *FileServiceLease
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		next, err := owner.SMB(account.ID).DisableForFileService(ctx, 7, old)
		done <- outcome{next, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not enter boundary")
	}
	if err := old.Verify(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent consumer entered mutation lock:", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	unblock.Do(func() { close(proceed) })
	var result outcome
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("atomic transfer did not settle")
	}
	if result.lease != nil {
		t.Cleanup(func() { result.lease.Release() })
	}
	if result.err != nil || result.lease == nil {
		t.Fatal("concurrent close disturbed revocation:", result.err)
	}
	select {
	case err := <-closed:
		if !errors.Is(err, ErrBusy) {
			t.Fatal("close observed a zero-consumer transfer interval:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not settle")
	}
	if err := result.lease.Verify(ctx); err != nil {
		t.Fatal("close lost the successor authority:", err)
	}
}

func TestSMBFileServiceDisableCancellationAfterIntentDoesNotYieldSuccessor(t *testing.T) {
	owner, backend, account := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Release() })
	operationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	backend.onDisable = cancel
	op := owner.SMB(account.ID)
	if successor, err := op.DisableForFileService(operationContext, 7, old); successor != nil || !errors.Is(err, ErrReview) {
		t.Fatal("cancellation after intent returned positive authority:", err)
	}
	journal, err := op.Load(ctx)
	if err != nil || journal.Phase != smbprovision.ReviewRequired || !backend.observation.Disabled {
		t.Fatal("interrupted transition was erased or represented as confirmed:", err)
	}
	if successor, err := op.DisableForFileService(ctx, journal.Revision, old); successor != nil || !errors.Is(err, ErrReview) || backend.disableCalls != 1 {
		t.Fatal("cancellation was retried or reset:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("interruption discarded the current consumer:", err)
	}
}

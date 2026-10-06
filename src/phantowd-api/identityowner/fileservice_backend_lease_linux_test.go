// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func TestSMBFileServiceLeaseCannotUseEqualEvidenceFromAnotherBackend(t *testing.T) {
	owner, backend, _ := fileServiceSMBLeaseFixture(t)
	other, foreign, _ := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	expected, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	control, err := other.FileServiceSnapshot(ctx)
	if err != nil || control.Fingerprint != expected.Fingerprint {
		t.Fatal("control owners do not have identical complete evidence:", err)
	}
	before, otherBefore := backend.observeSetCalls, foreign.observeSetCalls
	if lease, err := owner.RetainSMBFileServiceSnapshot(ctx, expected.Fingerprint, foreign); lease != nil || !errors.Is(err, ErrConflict) {
		if lease != nil {
			lease.Release()
		}
		t.Fatal("equal evidence admitted a foreign backend:", err)
	}
	if backend.observeSetCalls != before || foreign.observeSetCalls != otherBefore {
		t.Fatal("foreign binding attempted an observation")
	}
	lease, err := owner.RetainSMBFileServiceSnapshot(ctx, expected.Fingerprint, backend)
	if err != nil {
		t.Fatal("exact startup-bound backend refused:", err)
	}
	t.Cleanup(func() { lease.Release() })
	if err := lease.Verify(ctx); err != nil {
		t.Fatal("unchanged bound lease refused:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("bound consumer did not retain exact authority:", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("refused foreign binding leaked a consumer:", err)
	}
}

func TestSMBFileServiceLeaseInvalidCandidatesHaveNoEffects(t *testing.T) {
	owner, backend, _ := fileServiceSMBLeaseFixture(t)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var absent *modeledSMB
	for _, candidate := range []struct {
		name    string
		backend smbprovision.Backend
	}{
		{"nil", nil},
		{"typed-nil", absent},
		{"comparable-value", struct{ *modeledSMB }{backend}},
		{"noncomparable-value", struct {
			*modeledSMB
			items []byte
		}{backend, []byte{1}}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			before := backend.observeSetCalls
			lease, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, candidate.backend)
			if lease != nil {
				lease.Release()
			}
			if !errors.Is(err, ErrInvalid) || lease != nil || backend.observeSetCalls != before {
				t.Fatal("invalid object identity had effects or was accepted:", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, refusal := range []struct {
		name        string
		ctx         context.Context
		fingerprint [32]byte
		want        error
	}{
		{"nil-context", nil, evidence.Fingerprint, ErrUnavailable},
		{"canceled", canceled, evidence.Fingerprint, ErrUnavailable},
		{"zero-evidence", ctx, [32]byte{}, ErrInvalid},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			before := backend.observeSetCalls
			lease, err := owner.RetainSMBFileServiceSnapshot(refusal.ctx, refusal.fingerprint, backend)
			if lease != nil {
				lease.Release()
			}
			if !errors.Is(err, refusal.want) || lease != nil || backend.observeSetCalls != before {
				t.Fatal("pre-admission refusal had effects:", err)
			}
		})
	}
	if err := owner.Close(); err != nil {
		t.Fatal("refusals leaked retained authority:", err)
	}
}

func TestSMBFileServiceLeaseRevocationStillInvalidatesWithoutRevival(t *testing.T) {
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
	if _, err := json.Marshal(lease); err == nil {
		t.Fatal("backend-bound lease is serializable")
	}
	if err := json.Unmarshal([]byte(`{}`), lease); err == nil {
		t.Fatal("serialized input can address backend authority")
	}
	op := owner.SMB(account.ID)
	if err := op.Disable(ctx, 7); err != nil {
		t.Fatal("bound lease blocked explicit revocation:", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("changed journal/passdb admitted old bound lease:", err)
	}
	if stale, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend); stale != nil || !errors.Is(err, ErrConflict) {
		if stale != nil {
			stale.Release()
		}
		t.Fatal("correct backend accepted stale identity evidence:", err)
	}
	if err := op.Enable(ctx, 9); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("explicit re-enable revived the old lease:", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("review dropped lifetime retention:", err)
	}
}

func TestSMBFileServiceLeaseSharesCapacityAndExactBackendLifetime(t *testing.T) {
	backend := &closeCountingSMB{}
	owner, _, _ := fixtureWithSMB(t, backend)
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
	for index := range 16 {
		var lease *FileServiceLease
		var err error
		if index%2 == 0 {
			lease, err = owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
		} else {
			lease, err = owner.RetainFileServiceSnapshot(ctx, evidence.Fingerprint)
		}
		if err != nil {
			t.Fatal("mixed bounded consumer admission refused:", err)
		}
		leases = append(leases, lease)
	}
	if extra, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend); extra != nil || !errors.Is(err, ErrBusy) {
		if extra != nil {
			leases = append(leases, extra)
		}
		t.Fatal("bound consumers bypassed common capacity:", err)
	}
	copyOfFirst := *leases[0]
	if err := copyOfFirst.Release(); err != nil {
		t.Fatal(err)
	}
	if err := leases[0].Verify(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("released copy retained positive authority:", err)
	}
	replacement, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		t.Fatal("released common capacity was not reusable:", err)
	}
	leases = append(leases, replacement)
	if err := owner.Close(); !errors.Is(err, ErrBusy) || backend.closeCalls != 0 {
		t.Fatal("retained backend/store was released:", err)
	}
	for _, lease := range leases {
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.Close(); err != nil || backend.closeCalls != 1 {
		t.Fatal("exact backend was not closed once after drain:", err)
	}
}

// Go may give different zero-sized allocations the same pointer address.
// Such an adapter therefore cannot prove distinct authority by pointer identity.
type emptyLeaseSMB struct{}

func (*emptyLeaseSMB) Observe(context.Context, serviceaccounts.Account) (smbprovision.Observation, error) {
	return smbprovision.Observation{}, ErrUnavailable
}
func (*emptyLeaseSMB) CreateDisabled(context.Context, serviceaccounts.Account) error {
	return ErrUnavailable
}
func (*emptyLeaseSMB) SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error {
	return ErrUnavailable
}
func (*emptyLeaseSMB) Enable(context.Context, serviceaccounts.Account) error  { return ErrUnavailable }
func (*emptyLeaseSMB) Disable(context.Context, serviceaccounts.Account) error { return ErrUnavailable }

func TestSMBFileServiceLeaseRejectsZeroSizedBackendIdentity(t *testing.T) {
	backend := &emptyLeaseSMB{}
	owner, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lease, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend); lease != nil || !errors.Is(err, ErrInvalid) {
		if lease != nil {
			lease.Release()
		}
		t.Fatal("zero-sized allocation treated as unique backend authority:", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("refused backend identity leaked a consumer:", err)
	}
}

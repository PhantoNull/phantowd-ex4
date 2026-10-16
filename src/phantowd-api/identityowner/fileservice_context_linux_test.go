// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// Test-only backend fixed before Owner construction. Ending the original
// context after a complete modeled observation is not backend replacement.
type contextEndingSMB struct {
	modeledSMB
	finish func()
}

func (b *contextEndingSMB) ObserveAccounts(ctx context.Context, accounts []serviceaccounts.Account) ([]smbprovision.Observation, error) {
	observed, err := b.modeledSMB.ObserveAccounts(ctx, accounts)
	if b.finish != nil {
		b.finish()
	}
	return observed, err
}

func TestFileServiceLeaseAdmittedContextFailureKeepsCauseAndReview(t *testing.T) {
	for _, stage := range []string{"observation", "derivation"} {
		for _, expired := range []bool{false, true} {
			name := stage + "/canceled"
			if expired {
				name = stage + "/deadline"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					backend := &contextEndingSMB{}
					owner, _, _ := fileServiceSMBLeaseFixtureWithBackend(t, backend)
					before, err := owner.FileServiceSnapshot(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					lease, err := owner.RetainSMBFileServiceSnapshot(context.Background(), before.Fingerprint, backend)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { lease.Release() })
					privateCause := errors.New("PRIVATE context cause must not escape")
					var ctx context.Context
					var finish func()
					want := context.Canceled
					if expired {
						deadline, cancel := context.WithTimeoutCause(context.Background(), time.Second, privateCause)
						defer cancel()
						ctx, want = deadline, context.DeadlineExceeded
						finish = func() { time.Sleep(2 * time.Second); synctest.Wait() }
					} else {
						canceled, cancel := context.WithCancelCause(context.Background())
						defer cancel(nil)
						ctx = canceled
						finish = func() { cancel(privateCause) }
					}
					if stage == "observation" {
						backend.finish = finish
					}
					calls := backend.observeSetCalls
					derived := false
					err = lease.WithFileServiceSnapshot(ctx, func(FileServiceSnapshot) error {
						derived = true
						finish()
						return nil
					})
					if !errors.Is(err, ErrReview) || !errors.Is(err, want) || errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
						t.Fatalf("admitted context failure lost typed cause or leaked private cause: %v", err)
					}
					if backend.observeSetCalls != calls+1 || derived != (stage == "derivation") {
						t.Fatal("did not reach the actual single-observation/derivation boundary")
					}
					backend.finish = nil
					calls = backend.observeSetCalls
					if err := lease.Verify(context.Background()); !errors.Is(err, ErrReview) || backend.observeSetCalls != calls {
						t.Fatal("fresh context retried or revived reviewed authority:", err)
					}
					if err := owner.Close(); !errors.Is(err, ErrBusy) {
						t.Fatal("context failure released retained authority:", err)
					}
				})
			})
		}
	}
}

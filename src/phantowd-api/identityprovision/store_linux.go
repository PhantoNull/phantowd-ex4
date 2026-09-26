// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityprovision

import (
	"context"
	"errors"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// Backend is trusted in-process code, never a remote-supplied implementation.
// The future privileged owner must serialize ALL Unix/registry writers, pin
// qualified state, supervise bounded commands and supply fresh observations.
// This journal's lock alone does not own /etc, NSS or the reservation ledger.
type Backend interface {
	Observe(context.Context) (unixidentity.Snapshot, error)
	CreateGroup(context.Context, serviceaccounts.Account) error
	CreateUser(context.Context, serviceaccounts.Account) error
}

// Store is one operation in a caller-provisioned private directory. No generic
// Commit, reset, deletion or takeover method is exposed. Never copy a Store.
type Store struct {
	mu     sync.Mutex
	engine *revisionstore.Store[Journal]
}

func Open(directory string) (*Store, error) {
	e, err := revisionstore.OpenWithCodec(directory, revisionstore.Codec[Journal]{
		CurrentName: "identity-operation.json", PendingName: ".identity-operation.pending",
		MaxBytes: MaxBytes, Decode: Decode, Validate: Journal.Validate,
		Revision: func(j Journal) uint64 { return j.Revision },
	})
	if err != nil {
		return nil, err
	}
	return &Store{engine: e}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return nil
	}
	err := s.engine.Close()
	s.engine = nil
	return err
}

func (s *Store) Load() (Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return Journal{}, revisionstore.ErrClosed
	}
	return s.engine.Load()
}

// Begin requires an already durable disabled reservation and complete absence
// in the supplied trusted snapshot. A matching preexisting account is refused,
// never adopted. The caller holds its all-writer lock across snapshot and Begin.
func (s *Store) Begin(r serviceaccounts.Registry, id string, observed unixidentity.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	if r.Validate() != nil {
		return ErrInvalid
	}
	for _, a := range r.Accounts {
		if a.ID != id {
			continue
		}
		j := Journal{Format: Format, SchemaVersion: 1, Revision: 1, RegistryRevision: r.Revision, Account: a, Phase: Reserved}
		if j.Validate() != nil {
			return ErrInvalid
		}
		status, err := observed.Assess(a)
		if err != nil {
			return ErrObservation
		}
		if status != unixidentity.Absent {
			return ErrReview
		}
		return s.engine.Commit(0, j)
	}
	return ErrInvalid
}

// Step executes at most one native creation command. Intent must commit before
// invocation. Any resumed intent is ambiguous even when the account is absent:
// it moves to review-required without invoking a command. No implicit retry,
// repair, rollback/deletion, credential enablement or account adoption occurs.
// All errors from Backend are redacted. Storage errors retain their sentinels.
func (s *Store) Step(ctx context.Context, expected uint64, r serviceaccounts.Registry, backend Backend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	if ctx == nil || backend == nil {
		return ErrInvalid
	}
	j, err := s.engine.Load()
	if err != nil {
		return err
	}
	if expected != j.Revision || !j.matches(r) {
		return ErrConflict
	}
	if j.Phase == ReviewRequired {
		return ErrReview
	}
	if j.Phase == GroupIntent || j.Phase == UserIntent {
		return s.review(j)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	observed, err := backend.Observe(ctx)
	if err != nil {
		return ErrObservation
	} // no command has been dispatched
	detail, err := observed.Inspect(j.Account)
	if err != nil {
		return ErrObservation
	}
	if j.Phase == UnixConfirmed {
		if detail.Status != unixidentity.Observed {
			return s.review(j)
		}
		return nil // Unix identity only, not password/login or service readiness
	}
	if j.Phase == Reserved && detail.Status != unixidentity.Absent ||
		j.Phase == GroupConfirmed && !(detail.Status == unixidentity.Partial && detail.GroupPresent && !detail.UserPresent) {
		return s.review(j)
	}
	intent := j
	intent.Revision++
	intent.Phase = GroupIntent
	if j.Phase == GroupConfirmed {
		intent.Phase = UserIntent
	}
	if err := s.engine.Commit(j.Revision, intent); err != nil {
		return err
	}
	// Cancellation after durable intent is conservative uncertainty, not an
	// opportunity to erase history. Even failure before syscall entry is kept.
	if ctx.Err() != nil {
		return s.review(intent)
	}
	if intent.Phase == GroupIntent {
		err = backend.CreateGroup(ctx, intent.Account)
	} else {
		err = backend.CreateUser(ctx, intent.Account)
	}
	if err != nil {
		return s.review(intent)
	}
	observed, err = backend.Observe(ctx)
	if err != nil {
		return s.review(intent)
	}
	detail, err = observed.Inspect(intent.Account)
	if err != nil || ctx.Err() != nil {
		return s.review(intent)
	}
	if intent.Phase == GroupIntent && !(detail.Status == unixidentity.Partial && detail.GroupPresent && !detail.UserPresent) ||
		intent.Phase == UserIntent && detail.Status != unixidentity.Observed {
		return s.review(intent)
	}
	confirmed := intent
	confirmed.Revision++
	confirmed.Phase = GroupConfirmed
	if intent.Phase == UserIntent {
		confirmed.Phase = UnixConfirmed
	}
	// A failed confirmation leaves intent (or an uncertain commit) durable.
	// Reopen/reconcile before further work; never rerun the command here.
	return s.engine.Commit(intent.Revision, confirmed)
}

func (s *Store) review(j Journal) error {
	next := j
	next.Revision++
	next.Phase = ReviewRequired
	return errors.Join(ErrReview, s.engine.Commit(j.Revision, next))
}

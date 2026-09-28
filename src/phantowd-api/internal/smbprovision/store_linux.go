// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Linux durable state machine and interruption recovery implementation.
package smbprovision

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// Backend is trusted root-side code. Implementations use a fixed Samba config,
// bounded commands, stdin-only secrets and redacted observations. A caller must
// serialize all Unix, registry, passdb and journal writers around every method.
type Backend interface {
	Observe(context.Context, serviceaccounts.Account) (Observation, error)
	CreateDisabled(context.Context, serviceaccounts.Account) error
	SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error
}

// Store owns one account's Samba enrollment journal in a caller-provisioned
// private directory. It exposes no reset, delete, enable, or secret persistence.
// Never copy a Store.
type Store struct {
	mu     sync.Mutex
	engine *revisionstore.Store[Journal]
}

func Open(directory string) (*Store, error) {
	e, err := revisionstore.OpenWithCodec(directory, revisionstore.Codec[Journal]{
		CurrentName: "smb-operation.json", PendingName: ".smb-operation.pending",
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

// RecoverInterrupted converts a durable native-command intent to review. It
// never observes Samba or executes a command: once the caller reopens the
// owner, the prior command's outcome is uncertain and must not be replayed.
func (s *Store) RecoverInterrupted() (Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return Journal{}, revisionstore.ErrClosed
	}
	j, err := s.engine.Load()
	if err != nil {
		return Journal{}, err
	}
	if j.Phase != CreateIntent && j.Phase != PasswordIntent {
		return j, nil
	}
	next := j
	next.Revision++
	next.Phase = ReviewRequired
	if err := s.engine.Commit(j.Revision, next); err != nil {
		return Journal{}, err
	}
	return next, nil
}

// Begin binds a fresh journal to an existing owner-created Unix identity and
// refuses any pre-existing passdb entry. The parent identity authority must
// already have confirmed Unix creation and hold its global all-writer lock.
func (s *Store) Begin(ctx context.Context, nativeRevision uint64, account serviceaccounts.Account, backend Backend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	if ctx == nil || backend == nil || nativeRevision == 0 || !validAccount(account) {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	observed, err := backend.Observe(ctx, account)
	if err != nil {
		return ErrObservation
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if observed.validateFor(account, false) != nil {
		return ErrObservation
	}
	if observed.Present {
		return ErrReview
	}
	j := Journal{Format: Format, SchemaVersion: 1, Revision: 1,
		NativeRevision: nativeRevision, Account: account, Phase: Reserved}
	if j.Validate() != nil {
		return ErrInvalid
	}
	return s.engine.Commit(0, j)
}

func validAccount(account serviceaccounts.Account) bool {
	r, err := serviceaccounts.New(account.UID, account.UID)
	r.Accounts = []serviceaccounts.Account{account}
	return err == nil && r.Validate() == nil && account.State == serviceaccounts.Disabled
}

// Step creates at most the passdb entry. Durable intent precedes the native
// command; resumed intent is ambiguous and moves to review, never replay.
func (s *Store) Step(ctx context.Context, expected uint64, backend Backend) error {
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
	if expected != j.Revision {
		return ErrConflict
	}
	if j.Phase == ReviewRequired {
		return ErrReview
	}
	if j.Phase == CreateIntent || j.Phase == PasswordIntent {
		return s.review(j)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	observed, err := backend.Observe(ctx, j.Account)
	if err != nil {
		return ErrObservation
	}
	switch j.Phase {
	case Reserved:
		if observed.validateFor(j.Account, false) != nil || observed.Present {
			return s.review(j)
		}
		intent := j
		intent.Revision++
		intent.Phase = CreateIntent
		if err := s.engine.Commit(j.Revision, intent); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return s.review(intent)
		}
		if backend.CreateDisabled(ctx, j.Account) != nil || ctx.Err() != nil {
			return s.review(intent)
		}
		after, err := backend.Observe(ctx, j.Account)
		if err != nil || after.validateFor(j.Account, true) != nil || !after.Present {
			return s.review(intent)
		}
		confirmed := intent
		confirmed.Revision++
		confirmed.Phase = DisabledNoPassword
		confirmed.SID = after.SID
		return s.engine.Commit(intent.Revision, confirmed)
	case DisabledNoPassword:
		if observed.validateFor(j.Account, true) != nil || !observed.Present || observed.SID != j.SID {
			return s.review(j)
		}
		return ErrPending
	case CredentialSetDisabled:
		if observed.validateFor(j.Account, true) != nil || !observed.Present || observed.SID != j.SID {
			return s.review(j)
		}
		return nil
	default:
		return ErrInvalid
	}
}

// SetPasswordDisabled applies one bounded secret from memory only. It first
// commits intent, then calls a stdin-only backend, verifies the same SID remains
// disabled, and records confirmation without persisting the password. Any
// command error, cancellation after intent or uncertain observation is review.
func (s *Store) SetPasswordDisabled(ctx context.Context, expected uint64, secret []byte, backend Backend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	if ctx == nil || backend == nil || !ValidPassword(secret) {
		return ErrInvalid
	}
	j, err := s.engine.Load()
	if err != nil {
		return err
	}
	if expected != j.Revision {
		return ErrConflict
	}
	if j.Phase == ReviewRequired {
		return ErrReview
	}
	if j.Phase == CreateIntent || j.Phase == PasswordIntent {
		return s.review(j)
	}
	if j.Phase != DisabledNoPassword {
		return ErrConflict
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	observed, err := backend.Observe(ctx, j.Account)
	if err != nil {
		return ErrObservation
	}
	if observed.validateFor(j.Account, true) != nil || !observed.Present || observed.SID != j.SID {
		return s.review(j)
	}
	intent := j
	intent.Revision++
	intent.Phase = PasswordIntent
	if err := s.engine.Commit(j.Revision, intent); err != nil {
		return err
	}
	copyOfSecret := bytes.Clone(secret)
	defer clear(copyOfSecret)
	if ctx.Err() != nil || backend.SetPasswordDisabled(ctx, j.Account, copyOfSecret) != nil || ctx.Err() != nil {
		return s.review(intent)
	}
	after, err := backend.Observe(ctx, j.Account)
	if err != nil || after.validateFor(j.Account, true) != nil || !after.Present || after.SID != j.SID {
		return s.review(intent)
	}
	confirmed := intent
	confirmed.Revision++
	confirmed.Phase = CredentialSetDisabled
	return s.engine.Commit(intent.Revision, confirmed)
}

func (s *Store) review(j Journal) error {
	next := j
	next.Revision++
	next.Phase = ReviewRequired
	return errors.Join(ErrReview, s.engine.Commit(j.Revision, next))
}

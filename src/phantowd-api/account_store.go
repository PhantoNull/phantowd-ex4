// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"math"
	"sync"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

const minimumPasswordRunes = 15

var (
	errAccountConfigured  = errors.New("administrator account already configured")
	errAccountMissing     = errors.New("administrator account is not configured")
	errAccountUnavailable = errors.New("administrator state unavailable; restart and reconcile storage")
	errAccountUncertain   = errors.New("administrator state durability uncertain; restart and reconcile storage")
	errAccountClosed      = errors.New("administrator state closed")
	errAccountBusy        = errors.New("administrator state has another owner")
	errAccountConflict    = errors.New("administrator credential revision conflict")
	errPasswordUnchanged  = errors.New("new password must differ")
	errCredentials        = errors.New("invalid credentials")
	errInvalidUsername    = errors.New("invalid username")
	errShortPassword      = errors.New("password does not meet the minimum length")
)

// Implementations return only the errors above, never private paths/verifiers.
// The Linux adapter owns its durable backend for the entire API lifetime.
type accountBackend interface {
	Load() (admincredentials.Document, error)
	Initialize(string, string) error
	Replace(uint64, string) error
	Close() error
}

type accountStore struct {
	mu             sync.Mutex
	backend        accountBackend
	seenConfigured bool
	failure        error
}

func configuredAccountStateDirectory(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("account state directory must be explicitly configured")
	}
	return dir, nil
}

func openAccountStore(dir string) (*accountStore, error) {
	backend, err := openAccountBackend(dir)
	if err != nil {
		return nil, err
	}
	s := &accountStore{backend: backend}
	if _, err := s.loadLocked(); err != nil && !errors.Is(err, errAccountMissing) {
		_ = backend.Close()
		return nil, err
	}
	return s, nil
}

// loadLocked never returns cached credentials. Once configured state is lost,
// corrupt or uncertain this process remains unavailable even if someone puts
// the file back. Restart establishes a new owner and new in-memory sessions.
func (s *accountStore) loadLocked() (admincredentials.Document, error) {
	if s.backend == nil {
		return admincredentials.Document{}, errAccountClosed
	}
	if s.failure != nil {
		return admincredentials.Document{}, s.failure
	}
	d, err := s.backend.Load()
	if errors.Is(err, errAccountMissing) && !s.seenConfigured {
		return admincredentials.Document{}, errAccountMissing
	}
	if err != nil || d.Validate() != nil {
		s.failure = errAccountUnavailable
		if errors.Is(err, errAccountUncertain) {
			s.failure = errAccountUncertain
		}
		return admincredentials.Document{}, s.failure
	}
	s.seenConfigured = true
	return d, nil
}

func (s *accountStore) configured() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadLocked()
	if errors.Is(err, errAccountMissing) {
		return false, nil
	}
	return err == nil, err
}

func (s *accountStore) setup(ctx context.Context, username, password string) error {
	if !validUsername(username) {
		return errInvalidUsername
	}
	if !validSetupPassword(password) {
		return errShortPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadLocked()
	if err == nil {
		return errAccountConfigured
	}
	if !errors.Is(err, errAccountMissing) {
		return err
	}
	verifier, err := passwordhash.Hash(ctx, []byte(password))
	if err != nil {
		return err
	}
	if err := s.backend.Initialize(username, verifier); err != nil {
		if errors.Is(err, errAccountConfigured) {
			return errAccountConfigured
		}
		s.failure = errAccountUnavailable
		if errors.Is(err, errAccountUncertain) {
			s.failure = errAccountUncertain
		}
		return s.failure
	}
	s.seenConfigured = true
	return nil
}

func (s *accountStore) authenticate(ctx context.Context, username, password string) (bool, error) {
	if !validSetupPassword(password) {
		return false, errCredentials
	}
	s.mu.Lock()
	d, err := s.loadLocked()
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	var valid bool
	if !validUsername(username) || username != d.Admin.Username {
		_, err = passwordhash.Hash(ctx, []byte(password))
	} else {
		valid, err = passwordhash.Verify(ctx, []byte(password), d.Admin.PasswordHash)
	}
	if err != nil {
		return false, err
	}
	// KDF work does not retain the store lock. Recheck its exact snapshot before
	// accepting a result. Password replacement also revokes issuance epochs.
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.loadLocked()
	if err != nil {
		return false, err
	}
	if current != d {
		return false, errAccountUnavailable
	}
	return valid, nil
}

// changePassword derives the new verifier outside the adapter lock, then
// rechecks the full snapshot and authorizes/revokes sessions under that lock
// before committing. Session issuance uses the same account->session lock
// order. No old-credential session can escape the revocation/commit boundary.
// Storage failure AFTER revocation keeps sessions revoked and quarantines the
// process; no rollback to a cached verifier or automatic commit retry occurs.
func (s *accountStore) changePassword(ctx context.Context, currentPassword, newPassword string, revoke func() error) error {
	if !validSetupPassword(currentPassword) {
		return errCredentials
	}
	if !validSetupPassword(newPassword) {
		return errShortPassword
	}
	if currentPassword == newPassword {
		return errPasswordUnchanged
	}
	s.mu.Lock()
	d, err := s.loadLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if d.Revision == math.MaxUint64 {
		return errAccountConflict
	}
	valid, err := passwordhash.Verify(ctx, []byte(currentPassword), d.Admin.PasswordHash)
	if err != nil {
		return err
	}
	if !valid {
		return errCredentials
	}
	verifier, err := passwordhash.Hash(ctx, []byte(newPassword))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	latest, err := s.loadLocked()
	if err != nil {
		return err
	}
	if latest != d {
		return errAccountConflict
	}
	if revoke == nil {
		return errAccountUnavailable
	}
	if err := revoke(); err != nil {
		return err
	}
	if err := s.backend.Replace(d.Revision, verifier); err != nil {
		s.failure = errAccountUnavailable
		if errors.Is(err, errAccountUncertain) {
			s.failure = errAccountUncertain
		}
		return s.failure
	}
	return nil
}

// Prevent a concurrent failure/Close transition between the final account
// check and session issuance. fn must be short and must not reenter the store.
func (s *accountStore) withConfigured(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.loadLocked(); err != nil {
		return err
	}
	return fn()
}

func (s *accountStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend == nil {
		return nil
	}
	err := s.backend.Close()
	s.backend = nil
	if err != nil {
		return errAccountUnavailable
	}
	return nil
}

func validUsername(username string) bool { return admincredentials.ValidUsername(username) }

func validSetupPassword(password string) bool {
	return utf8.ValidString(password) && len(password) <= passwordhash.MaxPasswordLength &&
		utf8.RuneCountInString(password) >= minimumPasswordRunes
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package serviceaccountstore persists native identity reservations. It does
// not create Unix/Samba users, activate credentials or modify file ownership.
package serviceaccountstore

import (
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// Store intentionally does not expose generic Commit: replacing an arbitrary
// valid document could drop tombstones or reassign identity. Only the typed
// transitions below may write. All participants must honor the lifetime lock.
// Store must not be copied after construction.
type Store struct {
	mu     sync.Mutex
	engine *revisionstore.Store[serviceaccounts.Registry]
}

func Open(directory string) (*Store, error) {
	engine, err := revisionstore.OpenWithCodec(directory, revisionstore.Codec[serviceaccounts.Registry]{
		CurrentName: "service-accounts.json", PendingName: ".service-accounts.pending",
		MaxBytes: serviceaccounts.MaxInputBytes, Decode: serviceaccounts.Decode,
		Validate: serviceaccounts.Registry.Validate,
		Revision: func(r serviceaccounts.Registry) uint64 { return r.Revision },
	})
	if err != nil {
		return nil, err
	}
	return &Store{engine: engine}, nil
}

func (s *Store) Load() (serviceaccounts.Registry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return serviceaccounts.Registry{}, revisionstore.ErrClosed
	}
	return s.engine.Load()
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

// Initialize publishes only an empty reservation ledger and refuses existing
// state. It creates neither a directory nor any account and never resets state.
func (s *Store) Initialize(first, last uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	r, err := serviceaccounts.New(first, last)
	if err != nil {
		return err
	}
	return s.engine.Commit(0, r)
}

func (s *Store) Create(expected uint64, id, name string, reserved serviceaccounts.Reservations) error {
	return s.change(expected, func(r serviceaccounts.Registry) (serviceaccounts.Registry, error) {
		return r.Create(expected, id, name, reserved)
	})
}

func (s *Store) SetState(expected uint64, id, state string) error {
	return s.change(expected, func(r serviceaccounts.Registry) (serviceaccounts.Registry, error) {
		return r.SetState(expected, id, state)
	})
}

func (s *Store) change(expected uint64, plan func(serviceaccounts.Registry) (serviceaccounts.Registry, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	r, err := s.engine.Load()
	if err != nil {
		return err
	}
	next, err := plan(r)
	if err != nil {
		return err
	}
	return s.engine.Commit(expected, next)
}

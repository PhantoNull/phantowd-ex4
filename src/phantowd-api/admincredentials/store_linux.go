// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package admincredentials

import (
	"math"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

// Store owns a dedicated 0700 directory under trusted parents on a local
// filesystem with flock/rename/fsync support. All writers must honor its
// lifetime lock; do not run it alongside the old setup-only account writer.
// No method creates a directory, resets state, changes a name, or grants a
// session. The caller must independently authorize each credential change.
// A Store must not be copied after construction.
type Store struct {
	mu     sync.Mutex
	engine *revisionstore.Store[Document]
}

func Open(directory string) (*Store, error) {
	engine, err := revisionstore.OpenWithCodec(directory, revisionstore.Codec[Document]{
		CurrentName: "accounts.json", PendingName: ".accounts.pending",
		MaxBytes: MaxBytes, Decode: Decode, Validate: Document.Validate,
		Revision: func(d Document) uint64 { return d.Revision },
	})
	if err != nil {
		return nil, err
	}
	return &Store{engine: engine}, nil
}

// Load never serves a cached verifier. An uncertain publication poisons all
// operations until Close and a successful Open re-establish a sync boundary.
// Returned state is private: do not serialize it into logs or HTTP responses.
func (s *Store) Load() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return Document{}, revisionstore.ErrClosed
	}
	return s.engine.Load()
}

func (s *Store) Initialize(username, verifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	d := Document{Version: Version, Revision: 1, Admin: Account{Username: username, PasswordHash: verifier}}
	if d.Validate() != nil {
		return ErrInvalid
	}
	return s.engine.Commit(0, d)
}

// Replace preserves the administrator identity and publishes exactly one next
// revision. expected must identify the snapshot against which the caller
// verified the current password. This method accepts a validated verifier, not
// plaintext, and performs no authentication, KDF work, or session revocation.
// Replaying an uncertain response must use Load/reconciliation, never blind
// retries with an updated revision. ErrUncertain must fail authentication
// closed in the controller adapter, not fall back to cached state.
func (s *Store) Replace(expected uint64, verifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine == nil {
		return revisionstore.ErrClosed
	}
	d, err := s.engine.Load()
	if err != nil {
		return err
	}
	if expected == 0 || expected == math.MaxUint64 || d.Revision != expected {
		return revisionstore.ErrConflict
	}
	if verifier == d.Admin.PasswordHash {
		return ErrInvalid
	}
	d.Version, d.Revision, d.Admin.PasswordHash = Version, expected+1, verifier
	if d.Validate() != nil {
		return ErrInvalid
	}
	return s.engine.Commit(expected, d)
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

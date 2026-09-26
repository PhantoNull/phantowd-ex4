// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

type linuxAccountBackend struct{ store *admincredentials.Store }

func openAccountBackend(dir string) (accountBackend, error) {
	s, err := admincredentials.Open(dir)
	if err != nil {
		return nil, accountStorageError(err)
	}
	return &linuxAccountBackend{store: s}, nil
}

func accountStorageError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, revisionstore.ErrNotInitialized):
		return errAccountMissing
	case errors.Is(err, revisionstore.ErrBusy):
		return errAccountBusy
	case errors.Is(err, revisionstore.ErrUncertain):
		return errAccountUncertain
	case errors.Is(err, revisionstore.ErrClosed):
		return errAccountClosed
	case errors.Is(err, revisionstore.ErrConflict):
		return errAccountConflict
	default:
		return errAccountUnavailable
	}
}

func (b *linuxAccountBackend) Load() (admincredentials.Document, error) {
	d, err := b.store.Load()
	return d, accountStorageError(err)
}

func (b *linuxAccountBackend) Initialize(name, verifier string) error {
	err := b.store.Initialize(name, verifier)
	if errors.Is(err, revisionstore.ErrConflict) {
		return errAccountConfigured
	}
	return accountStorageError(err)
}

func (b *linuxAccountBackend) Close() error { return accountStorageError(b.store.Close()) }

func (b *linuxAccountBackend) Replace(expected uint64, verifier string) error {
	return accountStorageError(b.store.Replace(expected, verifier))
}

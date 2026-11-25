// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
	"golang.org/x/sys/unix"
)

type linuxAccountBackend struct{ store *admincredentials.Store }

func openInheritedAccountStore() (*accountStore, error) {
	store, err := openInheritedAdministratorCredentials()
	if err != nil {
		return nil, err
	}
	return ownAccountBackend(&linuxAccountBackend{store: store}, nil)
}

func openInheritedAdministratorCredentials() (*admincredentials.Store, error) {
	// Only an inherited, non-CLOEXEC directory is consumed. Do not wrap/close a
	// runtime-created FD when the parent forgot to supply the promised grant.
	flags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
	var st unix.Stat_t
	if err != nil || flags&unix.FD_CLOEXEC != 0 || unix.Fstat(3, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errAccountUnavailable
	}
	source := os.NewFile(3, "inherited-administrator-directory")
	store, err := admincredentials.OpenDirectory(source)
	if closeErr := source.Close(); closeErr != nil {
		if store != nil {
			store.Close()
		}
		return nil, errAccountUnavailable
	}
	if err != nil {
		return nil, accountStorageError(err)
	}
	return store, nil
}

var errAdministratorProvisioning = errors.New("administrator provisioning refused; reconcile local state")

func provisionInheritedAdministrator(ctx context.Context, input io.Reader) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errAdministratorProvisioning
	}
	store, err := openInheritedAdministratorCredentials()
	if err != nil {
		return errAdministratorProvisioning
	}
	provisionErr := provisionAdministrator(ctx, input, store)
	if errors.Join(provisionErr, store.Close()) != nil {
		return errAdministratorProvisioning
	}
	return nil
}

func provisionAdministrator(ctx context.Context, input io.Reader, store *admincredentials.Store) error {
	var request setupRequest
	keys := map[string]bool{"username": true, "password": true}
	if configjson.Decode(input, &request, 8*1024, 1, keys) != nil ||
		!validUsername(request.Username) || !validSetupPassword(request.Password) {
		return errAdministratorProvisioning
	}
	password := []byte(request.Password)
	defer clear(password)
	verifier, err := passwordhash.Hash(ctx, password)
	if err != nil || ctx.Err() != nil || store.InitializePristine(request.Username, verifier) != nil {
		return errAdministratorProvisioning
	}
	return nil
}

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

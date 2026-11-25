// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

type rc0ServiceIdentityRange struct {
	First uint32 `json:"first_id"`
	Last  uint32 `json:"last_id"`
}

func decodeRC0ServiceIdentityRange(input io.Reader) (rc0ServiceIdentityRange, error) {
	var allocation rc0ServiceIdentityRange
	fields := map[string]bool{"first_id": true, "last_id": true}
	if input == nil || configjson.Decode(input, &allocation, 512, 1, fields) != nil {
		return rc0ServiceIdentityRange{}, errRC0Review
	}
	if _, err := serviceaccounts.New(allocation.First, allocation.Last); err != nil {
		return rc0ServiceIdentityRange{}, errRC0Review
	}
	return allocation, nil
}

// The installer supplies the exact admitted state root and an independently
// chosen allocation window. The existing boot lock excludes live consumers.
func provisionInheritedRC0ServiceIdentities(ctx context.Context, input io.Reader) (result error) {
	if developmentBrowserEnrollment || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	allocation, err := decodeRC0ServiceIdentityRange(input)
	if err != nil {
		return err
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return identityowner.ProvisionInitial(ctx, root, allocation.First, allocation.Last)
}

// Older management-only state may omit this role. A pending stage or an
// invalid committed role requires review. Boot does not authorize allocating
// new identities without separate complete external-ownership evidence.
func openRC0ServiceIdentities(root *os.File) (*identityowner.Owner, error) {
	identities, err := identityowner.OpenProvisioned(root, func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{}, identityowner.ErrUnavailable
	})
	if identities == nil && errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return identities, err
}

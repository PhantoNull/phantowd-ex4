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
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
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
	identities, err := identityowner.OpenProvisioned(root, noRC0AllocationInventory)
	if identities == nil && errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return identities, err
}

func noRC0AllocationInventory(context.Context) (serviceaccounts.Reservations, error) {
	return serviceaccounts.Reservations{}, identityowner.ErrUnavailable
}

// The admitted state lock remains held while changing from the native-only
// observation to the same identity role with its fixed passdb backend.
func openRC0SambaIdentities(ctx context.Context, root *os.File, state *rc0SambaState) (
	*identityowner.Owner, *runtimebundle.SambaConfiguration, *smbexec.EnrollmentBackend, error) {
	if state == nil || state.check(root, rc0SambaStateRole) != nil {
		return nil, nil, nil, errRC0Review
	}
	native, err := openRC0ServiceIdentities(root)
	if native == nil {
		return nil, nil, nil, errors.Join(errRC0Review, err)
	}
	if err != nil {
		return native, nil, nil, err
	}
	lookup, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, native)
	if err := errors.Join(err, native.Close()); err != nil {
		return nil, nil, nil, err
	}
	configuration, err := runtimebundle.StageSambaEnrollmentConfiguration(ctx, lookup)
	if err != nil {
		return nil, configuration, nil, err
	}
	backend, err := smbexec.NewEnrollmentBackend(ctx, configuration, state.roles[0], state.roles[1])
	if err != nil {
		if backend != nil {
			err = errors.Join(err, backend.Close())
		}
		return nil, configuration, nil, err
	}
	identities, err := identityowner.OpenProvisionedWithSMBBackend(root, noRC0AllocationInventory, backend)
	if err != nil {
		return identities, configuration, nil, err
	}
	current, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, identities)
	if err != nil || current.Fingerprint() != lookup.Fingerprint() || state.check(root, rc0SambaStateRole) != nil {
		return identities, configuration, backend, errors.Join(errRC0Review, err)
	}
	return identities, configuration, backend, nil
}

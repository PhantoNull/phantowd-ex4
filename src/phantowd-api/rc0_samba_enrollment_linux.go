// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const (
	rc0CreateSambaAccount = "create-disabled"
	rc0SetSambaPassword   = "set-password"
	rc0EnableSambaAccount = "enable"
)

func configureInheritedRC0SambaAccount(ctx context.Context, action, id string, input io.Reader) (result error) {
	if developmentBrowserEnrollment || ctx == nil || ctx.Err() != nil ||
		os.Getuid() != 0 || os.Geteuid() != 0 || id == "" {
		return errRC0Review
	}
	var secret []byte
	switch action {
	case rc0CreateSambaAccount, rc0EnableSambaAccount:
	case rc0SetSambaPassword:
		if input == nil {
			return errRC0Review
		}
		raw, err := io.ReadAll(io.LimitReader(input, smbprovision.MaxPasswordBytes+2))
		defer clear(raw)
		secret = bytes.TrimSuffix(raw, []byte{'\n'})
		if err != nil || !smbprovision.ValidPassword(secret) {
			return errRC0Review
		}
	default:
		return errRC0Review
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
	samba, err := openRC0SambaState(root)
	if err != nil || samba == nil {
		return errors.Join(errRC0Review, err)
	}
	defer func() { result = errors.Join(result, samba.Close()) }()
	owner, configuration, _, err := openRC0SambaIdentities(ctx, root, samba)
	if configuration != nil {
		defer func() { result = errors.Join(result, configuration.Close()) }()
	}
	if owner != nil {
		defer func() { result = errors.Join(result, owner.Close()) }()
	}
	if err != nil {
		return err
	}
	return errors.Join(configureRC0SambaAccount(ctx, owner, action, id, secret), samba.check(root, rc0SambaStateRole))
}

func configureRC0SambaAccount(ctx context.Context, owner *identityowner.Owner, action, id string, secret []byte) error {
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return err
	}
	var account serviceaccounts.Account
	var nativeRevision uint64
	for i, candidate := range evidence.Registry.Accounts {
		if candidate.ID == id {
			account = candidate
			nativeRevision = evidence.Native[i].Revision
			break
		}
	}
	if nativeRevision == 0 {
		return errRC0Review
	}
	var journal smbprovision.Journal
	for _, identity := range evidence.Samba {
		if identity.Journal.Account.ID == id {
			journal = identity.Journal
			break
		}
	}
	if account.State == serviceaccounts.Enabled && action == rc0EnableSambaAccount && journal.Phase == smbprovision.Enabled {
		return nil
	}
	if account.State != serviceaccounts.Disabled {
		return errRC0Review
	}
	operation := owner.SMB(id)
	switch action {
	case rc0CreateSambaAccount:
		if journal.Revision == 0 {
			if err := operation.Begin(ctx, nativeRevision); err != nil {
				return err
			}
			journal, err = operation.Load(ctx)
			if err != nil {
				return err
			}
		}
		if journal.Phase == smbprovision.Reserved {
			return operation.Step(ctx, journal.Revision)
		}
		if journal.Phase == smbprovision.DisabledNoPassword {
			return nil
		}
	case rc0SetSambaPassword:
		if journal.Phase == smbprovision.DisabledNoPassword {
			return operation.SetPasswordDisabled(ctx, journal.Revision, secret)
		}
	case rc0EnableSambaAccount:
		if journal.Phase == smbprovision.CredentialSetDisabled {
			if err := operation.Enable(ctx, journal.Revision); err != nil {
				return err
			}
		} else if journal.Phase != smbprovision.Enabled {
			return errRC0Review
		}
		return owner.SetDesiredState(ctx, evidence.Registry.Revision, id, serviceaccounts.Enabled)
	}
	return errRC0Review
}

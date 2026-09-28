//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func qemuSMBEnrollmentAccount(account serviceaccounts.Account) bool {
	return account.ID == "second" && account.Name == "qpsecond" && account.State == serviceaccounts.Disabled && account.UID == account.GID
}

func exerciseQEMUOwnerSMBEnrollment(owner *identityowner.Owner, account serviceaccounts.Account) error {
	if owner == nil || !qemuSMBEnrollmentAccount(account) {
		return errors.New("owner-managed SMB fixture identity refused")
	}
	ctx := context.Background()
	operation := owner.SMB(account.ID)
	if err := operation.Begin(ctx, 5); err != nil {
		return fmt.Errorf("owner refused to begin Samba enrollment: %w", err)
	}
	if err := operation.Step(ctx, 1); err != nil {
		return fmt.Errorf("owner refused disabled Samba account creation: %w", err)
	}
	journal, err := operation.Load(ctx)
	if err != nil || journal.Phase != smbprovision.DisabledNoPassword || journal.Revision != 3 {
		return errors.New("owner did not confirm the new disabled Samba entry")
	}
	emptyAuth := smbFixtureRoot + "/owner-disabled-empty.auth"
	if err := os.WriteFile(emptyAuth, []byte("username = qpsecond\npassword = \n"), 0600); err != nil {
		return errors.New("could not create empty-credential fixture")
	}
	defer os.Remove(emptyAuth)
	output, err := smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", emptyAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if !smbFixtureDenied(output, err, "NT_STATUS_LOGON_FAILURE") {
		clear(output)
		return errors.New("new disabled owner-managed account accepted an empty credential")
	}
	clear(output)
	secret := []byte("public-qemu-owner-enrollment")
	if err := operation.SetPasswordDisabled(ctx, 3, secret); err != nil {
		clear(secret)
		return fmt.Errorf("owner refused disabled-password enrollment: %w", err)
	}
	clear(secret)
	journal, err = operation.Load(ctx)
	if err != nil || journal.Phase != smbprovision.CredentialSetDisabled || journal.Revision != 5 {
		return errors.New("owner did not confirm credentials while the Samba account stayed disabled")
	}
	if err := smbFixtureRequireDisabledAccount(smbFixtureRoot+"/smb.conf", account.Name); err != nil {
		return err
	}
	initialAuth := smbFixtureRoot + "/owner-disabled-initial.auth"
	if err := os.WriteFile(initialAuth, []byte("username = qpsecond\npassword = public-qemu-owner-enrollment\n"), 0600); err != nil {
		return errors.New("could not create owner credential fixture")
	}
	defer os.Remove(initialAuth)
	output, err = smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", initialAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if !smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
		clear(output)
		return errors.New("owner-managed initial credential authenticated before explicit enable")
	}
	clear(output)
	return nil
}

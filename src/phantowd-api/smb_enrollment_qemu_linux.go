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
	if err := exerciseQEMUIdentityChannel(owner, "smb-create"); err != nil {
		return fmt.Errorf("protected channel refused Samba enrollment setup: %w", err)
	}
	operation := owner.SMB(account.ID)
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
	if err := exerciseQEMUIdentityChannel(owner, "smb-password"); err != nil {
		return fmt.Errorf("protected channel refused disabled-password enrollment: %w", err)
	}
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
	if err := exerciseQEMUIdentityChannel(owner, "smb-enable"); err != nil {
		return fmt.Errorf("protected channel refused explicitly authorized enable: %w", err)
	}
	journal, err = operation.Load(ctx)
	if err != nil || journal.Phase != smbprovision.Enabled || journal.Revision != 7 {
		return errors.New("owner did not confirm explicit Samba enable")
	}
	output, err = smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", initialAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if err != nil {
		clear(output)
		return errors.New("new credential failed after explicit enable")
	}
	clear(output)
	output, err = smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", emptyAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if !smbFixtureDenied(output, err, "NT_STATUS_LOGON_FAILURE") {
		clear(output)
		return errors.New("empty credential authenticated after explicit enable")
	}
	clear(output)
	if err := exerciseQEMUIdentityChannel(owner, "smb-disable"); err != nil {
		return fmt.Errorf("protected channel refused explicit disable: %w", err)
	}
	journal, err = operation.Load(ctx)
	if err != nil || journal.Phase != smbprovision.Disabled || journal.Revision != 9 {
		return errors.New("owner did not confirm explicit Samba disable")
	}
	output, err = smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", initialAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if !smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
		clear(output)
		return errors.New("explicitly disabled account accepted a new authenticated connection")
	}
	clear(output)
	if err := exerciseQEMUIdentityChannel(owner, "smb-reenable"); err != nil {
		return fmt.Errorf("protected channel refused explicit re-enable: %w", err)
	}
	journal, err = operation.Load(ctx)
	if err != nil || journal.Phase != smbprovision.Enabled || journal.Revision != 11 {
		return errors.New("owner did not confirm explicit Samba re-enable")
	}
	output, err = smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", initialAuth, "//127.0.0.1/IPC$", "-c", "quit")
	if err != nil {
		clear(output)
		return errors.New("new credential failed after explicit re-enable")
	}
	clear(output)
	return nil
}

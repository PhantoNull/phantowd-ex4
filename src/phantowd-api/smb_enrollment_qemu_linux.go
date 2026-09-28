//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// qemuSMBEnrollmentBackend adapts the pinned guest Samba tools for one
// disposable fixture account and private test smb.conf. It is not a product
// executor: it accepts no paths or executable names from the caller, captures
// no mutation output, and uses only public fixture passwords.
type qemuSMBEnrollmentBackend struct {
	config string
}

func (b *qemuSMBEnrollmentBackend) Observe(ctx context.Context, account serviceaccounts.Account) (smbprovision.Observation, error) {
	if !qemuSMBEnrollmentAccount(account) || b == nil || b.config != smbFixtureRoot+"/smb.conf" {
		return smbprovision.Observation{}, errors.New("fixture passdb observation refused")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := smbFixtureCommandContext(commandCtx, "", "/usr/bin/pdbedit", "-L", "-v", "-s", b.config)
	if err != nil {
		clear(output)
		return smbprovision.Observation{}, errors.New("fixture passdb observation failed")
	}
	defer clear(output)
	return parseQEMUSMBObservation(output, account)
}

func (b *qemuSMBEnrollmentBackend) CreateDisabled(ctx context.Context, account serviceaccounts.Account) error {
	if !qemuSMBEnrollmentAccount(account) || b == nil || b.config != smbFixtureRoot+"/smb.conf" {
		return errors.New("fixture disabled-account creation refused")
	}
	return qemuSMBRunMutation(ctx, nil, "/usr/bin/smbpasswd", "-a", "-d", "-c", b.config, account.Name)
}

func (b *qemuSMBEnrollmentBackend) SetPasswordDisabled(ctx context.Context, account serviceaccounts.Account, secret []byte) error {
	if !qemuSMBEnrollmentAccount(account) || b == nil || b.config != smbFixtureRoot+"/smb.conf" || !smbprovision.ValidPassword(secret) {
		return errors.New("fixture disabled-password update refused")
	}
	input := make([]byte, 0, len(secret)*2+2)
	input = append(input, secret...)
	input = append(input, '\n')
	input = append(input, secret...)
	input = append(input, '\n')
	defer clear(input)
	return qemuSMBRunMutation(ctx, input, "/usr/bin/smbpasswd", "-s", "--set-password-disabled", "-c", b.config, account.Name)
}

func qemuSMBEnrollmentAccount(account serviceaccounts.Account) bool {
	return account.ID == "second" && account.Name == "qpsecond" && account.State == serviceaccounts.Disabled && account.UID == account.GID
}

func qemuSMBRunMutation(ctx context.Context, input []byte, executable string, args ...string) error {
	if ctx == nil {
		return errors.New("fixture command context missing")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, executable, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); commandCtx.Err() != nil || err != nil {
		return errors.New("fixture Samba mutation failed")
	}
	return nil
}

func parseQEMUSMBObservation(output []byte, account serviceaccounts.Account) (smbprovision.Observation, error) {
	type record struct {
		name, sid, flags string
	}
	var matches []record
	var current *record
	finish := func() {
		if current != nil && current.name == account.Name {
			matches = append(matches, *current)
		}
		current = nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Unix username:") {
			finish()
			current = &record{name: strings.TrimSpace(strings.TrimPrefix(line, "Unix username:"))}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "User SID:") {
			current.sid = strings.TrimSpace(strings.TrimPrefix(line, "User SID:"))
		}
		if strings.HasPrefix(line, "Account Flags:") {
			start, end := strings.IndexByte(line, '['), strings.LastIndexByte(line, ']')
			if start < 0 || end <= start {
				return smbprovision.Observation{}, errors.New("fixture passdb flags malformed")
			}
			current.flags = line[start+1 : end]
		}
	}
	finish()
	if len(matches) == 0 {
		return smbprovision.Observation{}, nil
	}
	if len(matches) != 1 || matches[0].sid == "" || matches[0].flags == "" {
		return smbprovision.Observation{}, errors.New("fixture passdb identity ambiguous")
	}
	return smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID, GID: account.GID,
		SID: matches[0].sid, Disabled: strings.Contains(matches[0].flags, "D")}, nil
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

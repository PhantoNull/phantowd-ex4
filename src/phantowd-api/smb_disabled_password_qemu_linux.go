//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// Characterize the pinned upstream CLI before using it behind a product
// credential owner. This is a fixed, disposable guest experiment, NOT an
// approved password update implementation. All passwords below are public
// fixture values; no production credential, caller path or user is accepted.
func exerciseQEMUDisabledPasswordBoundary(owner *identityowner.Owner, a serviceaccounts.Account) (result error) {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if a.ID != "second" || a.Name != "qpsecond" || a.State != serviceaccounts.Disabled || a.UID != a.GID || a.UID < 1804 || a.UID > 1810 {
		return errors.New("disabled-password fixture identity mismatch")
	}
	observed, err := unixidentity.ReadLocal("/etc", 0)
	if err != nil {
		return err
	}
	if state, err := observed.Assess(a); err != nil || state != unixidentity.Observed {
		return errors.New("disabled-password fixture Unix identity missing")
	}
	config := smbFixtureRoot + "/smb.conf"
	// Preserve the already generated account files/config exactly. The Samba
	// database alone is the subject of this isolated fixture.
	unchanged := map[string][]byte{}
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", config} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		unchanged[path] = data
	}
	const initial = "public-qemu-disabled-initial"
	const replacement = "public-qemu-disabled-replacement"
	const rejected = "public-qemu-disabled-rejected"
	for _, item := range []struct{ name, password string }{{"disabled-initial", initial}, {"disabled-replacement", replacement}, {"disabled-rejected", rejected}, {"disabled-empty", ""}} {
		path := smbFixtureRoot + "/" + item.name + ".auth"
		if err := os.WriteFile(path, []byte("username = qpsecond\npassword = "+item.password+"\n"), 0600); err != nil {
			return err
		}
		defer os.Remove(path)
	}
	command := func(input string, args ...string) error {
		output, err := smbFixtureCommand(input, "/usr/bin/smbpasswd", append(args, "-c", config, a.Name)...)
		if err != nil {
			return fmt.Errorf("disabled-password fixture command failed: %s", output)
		}
		return nil
	}
	client := func(auth string) ([]byte, error) {
		return smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", smbFixtureRoot+"/"+auth+".auth", "//127.0.0.1/IPC$", "-c", "quit")
	}
	if err := command(initial+"\n"+initial+"\n", "-s", "-a"); err != nil {
		return err
	}
	defer func() {
		if err := command("", "-x"); err != nil {
			result = errors.Join(result, errors.New("disabled-password fixture passdb cleanup failed"))
		}
	}()
	if _, err := client("disabled-initial"); err != nil {
		return errors.New("disabled-password initial login failed")
	}
	if err := command("", "-d"); err != nil {
		return err
	}
	out, err := client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("disabled-password initial disable not observed")
	}
	// Preserve the stock CLI contract: -d disables the account and clears
	// LOCAL_SET_PASSWORD, even if -s and password bytes are also supplied.
	// Verify the actual credential rather than trusting smbpasswd's exit code.
	if err := command(replacement+"\n"+replacement+"\n", "-s", "-d"); err != nil {
		return errors.New("legacy disable-with-stdin command failed")
	}
	if err := command("", "-e"); err != nil {
		return errors.New("legacy disable-with-stdin re-enable failed")
	}
	if _, err := client("disabled-initial"); err != nil {
		return errors.New("legacy -d unexpectedly replaced the existing password")
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("legacy -d unexpectedly installed the supplied password")
	}
	if err := command("", "-d"); err != nil {
		return errors.New("legacy behavior fixture re-disable failed")
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return fmt.Errorf("legacy -d did not disable the existing credential: output=%q command_error=%v", strings.TrimSpace(string(out)), err)
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return fmt.Errorf("legacy -d installed the supplied password: output=%q command_error=%v", strings.TrimSpace(string(out)), err)
	}
	if output, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "--set-password-disabled", "-c", config, a.Name); err == nil || !strings.Contains(string(output), "requires -s") {
		return fmt.Errorf("disabled-password option did not require stdin mode: %s", output)
	}
	// Simulate a compromised/unprivileged panel process. The account and config
	// stay unreadable to it; the new flag must fail at the root gate first.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nonroot := exec.CommandContext(ctx, "/usr/bin/smbpasswd", "-s", "--set-password-disabled", "-c", config, a.Name)
	nonroot.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	nonroot.Stdin = strings.NewReader(rejected + "\n" + rejected + "\n")
	nonroot.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	output, err := nonroot.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "only be used by root") {
		return errors.New("disabled-password option was not root-only")
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("rejected non-root request changed SMB state")
	}
	if err := command(rejected+"\n"+rejected+"\n", "-s", "-e", "--set-password-disabled"); err == nil {
		return errors.New("disabled-password option accepted an enable operation")
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("rejected enable combination changed account state")
	}
	out, err = client("disabled-rejected")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("rejected enable combination changed the password")
	}
	// This new CLI path must update the password and disabled flag in one SAM
	// update. The old and replacement credentials must both remain unable to
	// authenticate until a separate explicit enable operation.
	if err := command(replacement+"\n"+replacement+"\n", "-s", "--set-password-disabled"); err != nil {
		return err
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return fmt.Errorf("disabled-password update retained obsolete credential: output=%q command_error=%v", strings.TrimSpace(string(out)), err)
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return fmt.Errorf("disabled-password update did not keep replacement disabled: output=%q command_error=%v", strings.TrimSpace(string(out)), err)
	}
	if err := command("", "-e"); err != nil {
		return err
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("disabled-password update retained obsolete credential")
	}
	if _, err := client("disabled-replacement"); err != nil {
		return errors.New("disabled-password replacement rejected after explicit enable")
	}
	if err := command(rejected+"\n"+rejected+"\n", "-s", "--set-password-disabled"); err == nil {
		return errors.New("disabled-password option accepted an already enabled account")
	}
	if _, err := client("disabled-replacement"); err != nil {
		return errors.New("rejected enabled-account request changed the existing credential")
	}
	out, err = client("disabled-rejected")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("rejected enabled-account request installed its credential")
	}
	if err := command("", "-d"); err != nil {
		return err
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("disabled-password fixture cleanup did not retain disabled state")
	}
	// Characterize the first-enrollment CLI boundary, then repeat the absent to
	// disabled to credential-set-disabled flow through identityowner below.
	if err := command("", "-x"); err != nil {
		return errors.New("disabled-enrollment fixture could not reset its disposable passdb entry")
	}
	if err := command("", "-a", "-d"); err != nil {
		return errors.New("smbpasswd could not create a disabled no-password fixture account")
	}
	if err := smbFixtureRequireDisabledAccount(config, a.Name); err != nil {
		return err
	}
	out, err = client("disabled-empty")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("empty credential unexpectedly authenticated for new passdb account")
	}
	if err := command(initial+"\n"+initial+"\n", "-s", "--set-password-disabled"); err != nil {
		return errors.New("first password assignment to new disabled fixture account failed")
	}
	if err := smbFixtureRequireDisabledAccount(config, a.Name); err != nil {
		return err
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("first password assignment did not retain disabled state")
	}
	out, err = client("disabled-empty")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("first password assignment left an empty credential usable")
	}
	if err := command("", "-e"); err != nil {
		return errors.New("disabled-enrollment fixture could not perform its explicit enable")
	}
	if _, err := client("disabled-initial"); err != nil {
		return errors.New("first password assignment was not retained after explicit enable")
	}
	out, err = client("disabled-empty")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("empty credential authenticated after explicit enable")
	}
	if err := command("", "-d"); err != nil {
		return errors.New("disabled-enrollment fixture could not restore disabled state")
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("disabled-enrollment fixture did not restore disabled state")
	}
	if err := command("", "-x"); err != nil {
		return errors.New("could not reset the passdb entry before owner integration")
	}
	if err := exerciseQEMUOwnerSMBEnrollment(owner, a); err != nil {
		return err
	}
	for path, before := range unchanged {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			return errors.New("disabled-password fixture changed Unix state or config")
		}
	}
	fmt.Println("PHANTOWD_SMB_DISABLED_RESET_BOUNDARY legacy_reset_reenables=true combined_disable_skips_password=true scope=isolated-qemu-only")
	fmt.Println("PHANTOWD_SMB_DISABLED_PASSWORD_SET_READY replacement_set=true disabled_until_explicit_enable=true obsolete_password_denied=true unix_identity_unchanged=true scope=isolated-qemu-only")
	fmt.Println("PHANTOWD_SMB_DISABLED_ENROLLMENT_READY owner_lock=true intent_journal=true created_disabled=true empty_credential_denied=true password_set_disabled=true pre_enable_valid_denied=true enable_explicit=true same_sid_revalidated=true post_enable_valid_accepted=true post_enable_empty_denied=true scope=isolated-qemu-only")
	return nil
}

func smbFixtureRequireDisabledAccount(config, username string) error {
	output, err := smbFixtureCommand("", "/usr/bin/pdbedit", "-L", "-v", "-s", config, "-u", username)
	if err != nil {
		return fmt.Errorf("pdbedit could not observe disposable account state: %s", strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Account Flags:") {
			start, end := strings.IndexByte(line, '['), strings.LastIndexByte(line, ']')
			if start < 0 || end <= start || !strings.Contains(line[start+1:end], "D") {
				return fmt.Errorf("pdbedit did not report the disposable account disabled: %s", line)
			}
			return nil
		}
	}
	return errors.New("pdbedit output did not contain account flags for the disposable user")
}

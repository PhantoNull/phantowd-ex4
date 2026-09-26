//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// Characterize the pinned upstream CLI before using it behind a product
// credential owner. This is a fixed, disposable guest experiment, NOT an
// approved password update implementation. All passwords below are public
// fixture values; no production credential, caller path or user is accepted.
func exerciseQEMUDisabledPasswordBoundary(a serviceaccounts.Account) (result error) {
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
	for _, item := range []struct{ name, password string }{{"disabled-initial", initial}, {"disabled-replacement", replacement}} {
		path := smbFixtureRoot + "/" + item.name + ".auth"
		if err := os.WriteFile(path, []byte("username = qpsecond\npassword = "+item.password+"\n"), 0600); err != nil {
			return err
		}
		defer os.Remove(path)
	}
	command := func(input string, args ...string) error {
		_, err := smbFixtureCommand(input, "/usr/bin/smbpasswd", append(args, "-c", config, a.Name)...)
		if err != nil {
			return errors.New("disabled-password fixture command failed")
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
	// -d suppresses LOCAL_SET_PASSWORD: combining the switches does NOT set a
	// new password while keeping the account disabled. Verify the old one remains.
	if err := command(replacement+"\n"+replacement+"\n", "-s", "-d"); err != nil {
		return err
	}
	if err := command("", "-e"); err != nil {
		return err
	}
	if _, err := client("disabled-initial"); err != nil {
		return errors.New("combined disable unexpectedly replaced password")
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("combined disable unexpectedly accepted replacement")
	}
	if err := command("", "-d"); err != nil {
		return err
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("second disable not observed")
	}
	// Source inspection predicts that setting a password clears ACB_DISABLED
	// when no LM hash exists. Require actual network authentication, not exit 0.
	if err := command(replacement+"\n"+replacement+"\n", "-s"); err != nil {
		return err
	}
	if _, err := client("disabled-replacement"); err != nil {
		return errors.New("pinned upstream disabled-reset behavior changed; review capability")
	}
	out, err = client("disabled-initial")
	if !smbFixtureDenied(out, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("disabled reset retained old credential")
	}
	if err := command("", "-d"); err != nil {
		return err
	}
	out, err = client("disabled-replacement")
	if !smbFixtureDenied(out, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("disabled-password final disable not observed")
	}
	for path, before := range unchanged {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			return errors.New("disabled-password fixture changed Unix state or config")
		}
	}
	fmt.Println("PHANTOWD_SMB_DISABLED_RESET_BOUNDARY legacy_reset_reenables=true combined_disable_skips_password=true product_path_approved=false scope=isolated-qemu-only")
	return nil
}

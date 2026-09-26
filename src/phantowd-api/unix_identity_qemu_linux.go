//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// QEMU-only connection between registry allocation and actual guest Unix
// identity. This fixed fixture is not a general privileged account executor.
func exerciseQEMUUnixIdentity() (result error) {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	observe := func() (unixidentity.Snapshot, error) {
		passwd, err := os.Open("/etc/passwd")
		if err != nil {
			return unixidentity.Snapshot{}, err
		}
		defer passwd.Close()
		groups, err := os.Open("/etc/group")
		if err != nil {
			return unixidentity.Snapshot{}, err
		}
		defer groups.Close()
		return unixidentity.Parse(passwd, groups)
	}
	before, err := observe()
	if err != nil {
		return err
	}
	reserved, err := before.Reservations()
	if err != nil {
		return err
	}
	r, err := serviceaccounts.New(1800, 1810)
	if err != nil {
		return err
	}
	r, err = r.Create(1, "managed", "qpmanaged", reserved)
	if err != nil {
		return err
	}
	a := r.Accounts[0]
	// The existing SMB fixture owns group 1800 and users 1801..1803.
	if a.UID <= 1803 {
		return errors.New("Unix observer missed existing fixture identities")
	}
	if status, err := before.Assess(a); err != nil || status != unixidentity.Absent {
		return errors.New("new fixture identity not absent")
	}
	createdGroup, createdUser := false, false
	defer func() {
		if createdUser {
			// Pinned BusyBox deluser also removes the same-named group. Do not
			// blindly delete it twice or treat arbitrary command errors as OK.
			if _, err := smbFixtureCommand("", "/usr/sbin/deluser", a.Name); err != nil {
				result = errors.Join(result, errors.New("managed fixture user cleanup failed"))
			}
		} else if createdGroup {
			if _, err := smbFixtureCommand("", "/usr/sbin/delgroup", a.Name); err != nil {
				result = errors.Join(result, errors.New("managed fixture group cleanup failed"))
			}
		}
		cleaned, err := observe()
		if err != nil {
			result = errors.Join(result, errors.New("managed fixture cleanup observation failed"))
			return
		}
		if status, err := cleaned.Assess(a); err != nil || status != unixidentity.Absent {
			result = errors.Join(result, errors.New("managed fixture identity remained after cleanup"))
		}
	}()
	if _, err := smbFixtureCommand("", "/usr/sbin/addgroup", "-g", strconv.FormatUint(uint64(a.GID), 10), a.Name); err != nil {
		return errors.New("managed fixture group creation failed")
	}
	createdGroup = true
	partial, err := observe()
	if err != nil {
		return err
	}
	if status, err := partial.Assess(a); err != nil || status != unixidentity.Partial {
		return errors.New("group-only fixture not classified as partial")
	}
	if _, err := smbFixtureCommand("", "/usr/sbin/adduser", "-D", "-H", "-s", "/sbin/nologin", "-G", a.Name, "-u", strconv.FormatUint(uint64(a.UID), 10), a.Name); err != nil {
		return errors.New("managed fixture user creation failed")
	}
	createdUser = true
	after, err := observe()
	if err != nil {
		return err
	}
	if status, err := after.Assess(a); err != nil || status != unixidentity.Observed {
		return errors.New("provisioned fixture identity does not match registry")
	}
	conflicting := a
	conflicting.UID++
	conflicting.GID++
	if status, err := after.Assess(conflicting); err != nil || status != unixidentity.Conflict {
		return errors.New("mismatched fixture identity not refused")
	}
	exclusions, err := after.Reservations()
	if err != nil {
		return err
	}
	empty, _ := serviceaccounts.New(1800, 1810)
	if _, err := empty.Create(1, "other", a.Name, exclusions); !errors.Is(err, serviceaccounts.ErrCollision) {
		return errors.New("observed fixture name allocated twice")
	}
	return nil
}

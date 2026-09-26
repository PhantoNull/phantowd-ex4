//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// QEMU-only connection between registry allocation and actual guest Unix
// identity. This fixed fixture is not a general privileged account executor.
func exerciseQEMUUnixIdentity() (result error) {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	observe := func() (unixidentity.Snapshot, error) {
		return unixidentity.ReadLocal("/etc", 0)
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
	root := smbFixtureRoot + "/identity-authority"
	for _, path := range []string{root, root + "/registry", root + "/operations"} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	seed, err := serviceaccountstore.Open(root + "/registry")
	if err != nil {
		return err
	}
	err = seed.Initialize(1800, 1810)
	closeErr := seed.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	// The guarded disposable guest has no imported/offline data identities.
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	owner, err := identityowner.Open(root, inventory)
	if err != nil {
		return err
	}
	defer owner.Close()
	allocated, err := owner.Reserve(context.Background(), 1, a.ID, a.Name)
	if err != nil || allocated != a {
		return errors.New("authority reservation mismatch")
	}
	competing, err := identityowner.Open(root, inventory)
	if competing != nil {
		competing.Close()
	}
	if !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("authority lifetime lease bypassed")
	}
	if err := exerciseQEMUIdentityChannel(owner.Operation(a.ID), "group"); err != nil {
		return err
	}
	createdGroup = true
	partial, err := observe()
	if err != nil {
		return err
	}
	if status, err := partial.Assess(a); err != nil || status != unixidentity.Partial {
		return errors.New("group-only fixture not classified as partial")
	}
	// Resume a confirmed group after store close/reopen; this is not an
	// ambiguous dispatch. The next command still needs fresh group-only state.
	if _, err := owner.Reserve(context.Background(), 2, "other", "qpother"); !errors.Is(err, identityowner.ErrPending) {
		return errors.New("pending operation did not freeze allocation")
	}
	if err := owner.Close(); err != nil {
		return err
	}
	owner, err = identityowner.Open(root, inventory)
	if err != nil {
		return err
	}
	defer owner.Close()
	if err := exerciseQEMUIdentityChannel(owner.Operation(a.ID), "user"); err != nil {
		return err
	}
	createdUser = true
	completed, err := owner.Operation(a.ID).Load(context.Background())
	if err != nil || completed.Phase != identityprovision.UnixConfirmed || completed.Revision != 5 {
		return errors.New("managed fixture journal incomplete")
	}
	after, err := observe()
	if err != nil {
		return err
	}
	if status, err := after.Assess(a); err != nil || status != unixidentity.Observed {
		return errors.New("provisioned fixture identity does not match registry")
	}
	// Inspect only this generated guest account. Never return shadow bytes.
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return err
	}
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	locked, noLogin := false, false
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == a.Name {
			noLogin = fields[6] == "/sbin/nologin"
			if _, err := os.Lstat(fields[5]); !errors.Is(err, os.ErrNotExist) {
				return errors.New("native fixture unexpectedly created a home")
			}
		}
	}
	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 9 && fields[0] == a.Name {
			locked = strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")
		}
	}
	if !locked || !noLogin {
		return errors.New("native fixture login policy mismatch")
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

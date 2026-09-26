//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
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
	journalPath := smbFixtureRoot + "/identity-operation"
	if err := os.Mkdir(journalPath, 0700); err != nil {
		return err
	}
	journal, err := identityprovision.Open(journalPath)
	if err != nil {
		return err
	}
	defer journal.Close()
	if err := journal.Begin(r, a.ID, before); err != nil {
		return err
	}
	executor, err := identityexec.Open(a)
	if err != nil {
		return err
	}
	defer executor.Close()
	backend := qemuNativeIdentityBackend{expected: a, executor: executor, groupCreated: &createdGroup, userCreated: &createdUser}
	if err := journal.Step(context.Background(), 1, r, backend); err != nil {
		return err
	}
	partial, err := observe()
	if err != nil {
		return err
	}
	if status, err := partial.Assess(a); err != nil || status != unixidentity.Partial {
		return errors.New("group-only fixture not classified as partial")
	}
	// Resume a confirmed group after store close/reopen; this is not an
	// ambiguous dispatch. The next command still needs fresh group-only state.
	if err := journal.Close(); err != nil {
		return err
	}
	journal, err = identityprovision.Open(journalPath)
	if err != nil {
		return err
	}
	defer journal.Close()
	if err := journal.Step(context.Background(), 3, r, backend); err != nil {
		return err
	}
	completed, err := journal.Load()
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

// Deliberately fixed QEMU backend, not a deployable privileged executor. The
// caller serializes this isolated scenario; only its exact new account is valid.
type qemuNativeIdentityBackend struct {
	expected                  serviceaccounts.Account
	executor                  *identityexec.Executor
	groupCreated, userCreated *bool
}

func (b qemuNativeIdentityBackend) Observe(ctx context.Context) (unixidentity.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return unixidentity.Snapshot{}, err
	}
	if err := guardQEMUDataVolume(); err != nil {
		return unixidentity.Snapshot{}, err
	}
	if b.executor == nil {
		return unixidentity.Snapshot{}, errors.New("native executor absent")
	}
	return b.executor.Observe(ctx)
}

func (b qemuNativeIdentityBackend) CreateGroup(ctx context.Context, a serviceaccounts.Account) error {
	if err := b.check(ctx, a); err != nil {
		return err
	}
	err := b.executor.CreateGroup(ctx, a)
	if err == nil {
		*b.groupCreated = true
	}
	return err
}

func (b qemuNativeIdentityBackend) CreateUser(ctx context.Context, a serviceaccounts.Account) error {
	if err := b.check(ctx, a); err != nil {
		return err
	}
	err := b.executor.CreateUser(ctx, a)
	if err == nil {
		*b.userCreated = true
	}
	return err
}

func (b qemuNativeIdentityBackend) check(ctx context.Context, a serviceaccounts.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a != b.expected || a.ID != "managed" || a.Name != "qpmanaged" || a.UID <= 1803 || a.UID > 1810 || a.GID != a.UID || a.State != serviceaccounts.Disabled || b.groupCreated == nil || b.userCreated == nil || b.executor == nil {
		return errors.New("unexpected QEMU native identity")
	}
	return guardQEMUDataVolume()
}

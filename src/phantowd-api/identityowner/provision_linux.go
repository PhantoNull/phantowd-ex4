// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"golang.org/x/sys/unix"
)

const (
	stateDirectory = "service-identities"
	stateStage     = ".service-identities.provisioning"
)

// ProvisionInitial publishes a fresh ledger for a supervisor-supplied native
// ID range under its admitted private state directory. It makes no Unix or
// Samba accounts. A staged or existing identity authority is never replaced.
func ProvisionInitial(ctx context.Context, parent *os.File, first, last uint32) (result error) {
	if ctx == nil || ctx.Err() != nil || parent == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrInvalid
	}
	if _, err := serviceaccounts.New(first, last); err != nil {
		return ErrInvalid
	}
	root, err := borrowPrivateDirectory(parent)
	if err != nil {
		return err
	}
	defer func() {
		if err := unix.Close(root); err != nil {
			result = errors.Join(result, ErrReview)
		}
	}()
	if !identityStateAbsent(root, stateStage) {
		return ErrReview
	}
	if !identityStateAbsent(root, stateDirectory) {
		return ErrConflict
	}
	// The fixed stage and final no-replace rename arbitrate competing calls,
	// including when the supervisor already holds its own parent lock.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if unix.Mkdirat(root, stateStage, 0700) != nil || unix.Fsync(root) != nil {
		return ErrReview
	}
	stage, original, err := openPrivateDirectoryAt(root, stateStage)
	if err != nil {
		return ErrReview
	}
	err = initializeIdentityStage(stage, first, last)
	if closeErr := unix.Close(stage); err != nil || closeErr != nil || ctx.Err() != nil {
		return ErrReview
	}
	var named unix.Stat_t
	if unix.Fstatat(root, stateStage, &named, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil ||
		!privateDirectory(named) || named.Dev != original.Dev || named.Ino != original.Ino {
		return ErrReview
	}
	if unix.Renameat2(root, stateStage, root, stateDirectory, unix.RENAME_NOREPLACE) != nil || unix.Fsync(root) != nil {
		return ErrReview
	}
	return nil
}

func initializeIdentityStage(stage int, first, last uint32) error {
	for _, role := range []string{"registry", "operations"} {
		if err := unix.Mkdirat(stage, role, 0700); err != nil {
			return err
		}
	}
	registry, _, err := openPrivateDirectoryAt(stage, "registry")
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(registry), "identity-ledger-stage")
	store, err := serviceaccountstore.OpenFromDirectory(file)
	if err != nil {
		return errors.Join(err, file.Close())
	}
	err = errors.Join(store.Initialize(first, last), store.Close(), file.Close())
	if err != nil {
		return err
	}
	return unix.Fsync(stage)
}

// OpenProvisioned opens the fixed committed role from the original admitted
// RC0 state directory. A pending stage takes precedence over the final role.
func OpenProvisioned(parent *os.File, inventory Inventory) (_ *Owner, result error) {
	if parent == nil || inventory == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInvalid
	}
	root, err := borrowPrivateDirectory(parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unix.Close(root); err != nil {
			result = errors.Join(result, ErrReview)
		}
	}()
	if !identityStateAbsent(root, stateStage) {
		return nil, ErrReview
	}
	dir, _, err := openPrivateDirectoryAt(root, stateDirectory)
	if err != nil {
		return nil, err
	}
	return openOwned(dir, ownerDependencies(inventory))
}

func identityStateAbsent(root int, name string) bool {
	var stat unix.Stat_t
	return errors.Is(unix.Fstatat(root, name, &stat, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT), unix.ENOENT)
}

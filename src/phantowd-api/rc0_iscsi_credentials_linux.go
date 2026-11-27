// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"golang.org/x/sys/unix"
)

func provisionInheritedRC0ISCSICredentials(ctx context.Context, installation string, input io.Reader) (result error) {
	if developmentBrowserEnrollment || ctx == nil || ctx.Err() != nil || installation == "" ||
		os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	known, proofInfo, err := readRC0PolicyGrant(4)
	if err != nil {
		return err
	}
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	if _, err := observeRC0PrivateStateDirectory(root); err != nil {
		return err
	}
	policy, err := openRC0Role(root, "nas-policy", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, policy.Close()) }()
	owner, err := admitRC0Policy(ctx, policy, installation, known, proofInfo)
	if owner != nil {
		defer func() { result = errors.Join(result, owner.Close()) }()
	}
	if err != nil {
		return err
	}
	document, err := owner.Snapshot(ctx)
	if err != nil {
		return err
	}
	claim, err := owner.Acquire(ctx, document.Revision)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, claim.Release()) }()
	return iscsicredentials.ProvisionInitial(ctx, root, claim, input)
}

type rc0ISCSICredentials struct {
	directory *os.File
	owner     *iscsicredentials.Owner
}

func openRC0ISCSICredentials(ctx context.Context, root *os.File) (_ *rc0ISCSICredentials, result error) {
	if !rc0AbsentRole(root, iscsicredentials.InitialStage) {
		return nil, errRC0Review
	}
	dir, err := openRC0Role(root, iscsicredentials.InitialRole, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	vault := &rc0ISCSICredentials{directory: dir}
	defer func() {
		if result != nil {
			result = errors.Join(result, vault.close())
		}
	}()
	if err := checkRC0ISCSICredentialDirectory(root, dir); err != nil {
		return nil, err
	}
	vault.owner, err = iscsicredentials.OpenDirectory(dir)
	if err != nil {
		return nil, err
	}
	if err := vault.check(ctx, root); err != nil {
		return nil, err
	}
	return vault, nil
}

func checkRC0ISCSICredentialDirectory(root, dir *os.File) error {
	info, err := observeRC0PrivateStateDirectory(dir)
	if err != nil || !sameRC0PrivateStateRole(root, iscsicredentials.InitialRole, info) ||
		!rc0AbsentRole(root, iscsicredentials.InitialStage) {
		return errRC0Review
	}
	return nil
}

func (v *rc0ISCSICredentials) check(ctx context.Context, root *os.File) error {
	if err := checkRC0ISCSICredentialDirectory(root, v.directory); err != nil {
		return err
	}
	directory, err := openRC0Role(v.directory, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(2)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) != 1 ||
		names[0] != iscsicredentials.CurrentFile {
		return errRC0Review
	}
	return v.owner.Verify(ctx)
}

func (v *rc0ISCSICredentials) close() error {
	var err error
	if v.owner != nil {
		err = v.owner.Close()
	}
	return errors.Join(err, v.directory.Close())
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"golang.org/x/sys/unix"
)

// The platform launcher authorizes the parent and supplies independent policy
// and TLS confirmation. Only the fixed provisioned child can supply state.
func publishInheritedRC0State(ctx context.Context, installation, address, origin, fingerprint string) (result error) {
	plan := rc0BootPlan{Format: rc0BootFormat, Installation: installation, Address: address, Origin: origin, TLSLeafSHA256: fingerprint}
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 || !safeRC0RunDirectory() ||
		!plan.validTransport() || !validRC0SHA256(fingerprint) {
		return errRC0Review
	}
	parent, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	policy, proof, err := readRC0PolicyGrant(4)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(policy)
	plan.PolicySHA256 = hex.EncodeToString(digest[:])
	boot, err := lockRC0BootLifecycle()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, boot.Close()) }()
	if !rc0BootServiceAbsent() || ctx.Err() != nil {
		return errRC0Review
	}
	medium, err := lockRC0StateRoot(parent)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, medium.Close()) }()
	if !rc0AbsentRole(medium, rc0StateStage) {
		return errRC0Review
	}
	state, err := openRC0Role(medium, rc0StateName, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	plan.StateMountID, plan.StateRootInode, err = rc0StateIdentity(root)
	if err != nil {
		return err
	}
	policyDir, err := openRC0Role(root, "nas-policy", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, policyDir.Close()) }()
	owner, err := admitRC0Policy(ctx, policyDir, installation, policy, proof)
	if owner != nil {
		defer func() { result = errors.Join(result, owner.Close()) }()
	}
	if err != nil {
		return err
	}
	accounts, err := checkRC0ProvisionedAdministrator(root)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, accounts.Close()) }()
	identity, err := openRC0TLSIdentity(root)
	if err != nil {
		return err
	}
	pair, err := readTLSIdentity(identity, 0)
	if errors.Join(err, identity.Close()) != nil || len(pair.Certificate) == 0 || tlsLeafFingerprint(pair.Certificate[0]) != fingerprint {
		return errRC0Review
	}
	public, err := parseOrigin(origin)
	if err != nil || validateTLSLeaf(&pair, public.Hostname(), time.Now()) != nil {
		return errRC0Review
	}
	return stageRC0BootGrant(ctx, root, plan, policy)
}

// The read-only check uses the account store's own directory lock and codec.
// The supervisor opens the account store again as the confined API principal.
func checkRC0ProvisionedAdministrator(root *os.File) (*os.File, error) {
	uid, gid, err := managementAPIIdentity()
	if err != nil {
		return nil, err
	}
	accounts, err := openRC0Role(root, "accounts", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return nil, err
	}
	fd := int(accounts.Fd())
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode != unix.S_IFDIR|0700 || info.Uid != uid || info.Gid != gid ||
		unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || !rc0AbsentRole(accounts, ".accounts.pending") {
		return nil, errors.Join(errRC0Review, accounts.Close())
	}
	file, err := openRC0OwnedFile(accounts, "accounts.json", uid, admincredentials.MaxBytes)
	if err != nil {
		return nil, errors.Join(err, accounts.Close())
	}
	data, _, err := readPrivateStartupFile(file, uid, admincredentials.MaxBytes)
	defer clear(data)
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, errors.Join(err, accounts.Close())
	}
	if _, err := admincredentials.Decode(bytes.NewReader(data)); err != nil {
		return nil, errors.Join(errRC0Review, accounts.Close())
	}
	return accounts, nil
}

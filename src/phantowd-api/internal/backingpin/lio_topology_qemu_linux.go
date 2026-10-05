//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Foreign NEW configfs objects belong only to this disposable test controller.
// They must never be adopted/removed by the backend or hide behind owned checks.
func qemuLIOForeignTopology(ctx context.Context, owner *writableOwner, backend *qemuLIOTargetBackend, kind string,
	policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, lease *mountowner.MountedVolumeSetLease) error {
	const tpg = lioCredentialFixtureTarget + "/tpgt_1"
	var path string
	switch kind {
	case "foreign-acl":
		path = tpg + "/acls/iqn.2026-10.invalid.phantowd:unowned"
	case "foreign-lun":
		path = tpg + "/lun/lun_8"
	case "foreign-grant":
		path = tpg + "/acls/" + lioCredentialFixturePeer + "/lun_8"
	default:
		return ErrInvalid
	}
	if os.Mkdir(path, 0755) != nil {
		return ErrUnavailable
	}
	foreign, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	defer foreign.Close()
	id, err := lioConfigIdentity(foreign, true)
	if err != nil {
		return err
	}
	if !errors.Is(owner.observe(ctx), ErrReview) || owner.phase != writableReview || owner.released ||
		backend.stops != 1 || !backend.liveAtStop || !backend.stopAttempted || backend.stopped || backend.checkEntries() != nil ||
		lioBackendCheck(backend.tpg, "enable", "0") != nil || owner.policy == nil || owner.credentials == nil {
		return ErrReview
	}
	if !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
		return ErrReview
	}
	for _, member := range owner.group {
		if member.file == nil || !errors.Is(member.pin.Close(), ErrBusy) {
			return ErrReview
		}
		if _, err := member.file.Stat(); err != nil {
			return ErrReview
		}
	}
	for _, peer := range backend.peers {
		if _, err := peer.Incoming.WriteTo(io.Discard); err != nil {
			return ErrReview
		}
	}
	for _, operation := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(operation(), ErrReview) {
			return ErrReview
		}
	}
	current, err := os.Open(path)
	if err != nil {
		return ErrReview
	}
	observed, observeErr := lioConfigIdentity(current, true)
	closeErr := current.Close()
	retained, retainErr := lioConfigIdentity(foreign, true)
	if observeErr != nil || closeErr != nil || retainErr != nil || observed != id || retained != id || backend.stops != 1 {
		return ErrReview
	}
	// No portal/login or backing was added by this controller. Owner's stop
	// verified no owned sessions before partial removal. The TPG remains disabled.
	// Removing our own empty object is independent fixture disposal, not retry.
	if lioBackendCheck(backend.tpg, "enable", "0") != nil || os.Remove(path) != nil || qemuLIORemoveRemainingFixture(ctx, backend.lioBackend) != nil {
		return ErrReview
	}
	owner.mu.Lock()
	err = owner.releaseLocked()
	owner.mu.Unlock()
	if err != nil || !owner.released || owner.phase != writableReview || backend.stops != 1 || backend.stopped {
		return ErrReview
	}
	return nil
}

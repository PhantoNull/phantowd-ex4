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
	case "foreign-portal":
		path = tpg + "/np/127.0.0.1:3261" // Guest loopback only; no host listener/NIC.
	case "extra-tpg":
		path = lioCredentialFixtureTarget + "/tpgt_2"
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
	if kind == "extra-tpg" && lioBackendCheck(foreign, "enable", "0") != nil {
		return ErrReview // NEW default-disabled TPG; never enable/add a portal.
	}
	// An extra sibling TPG blocks removal of the target itself, AFTER owned
	// tpgt_1 is disabled/removed/closed. Other foreign children block tpgt_1
	// removal, leaving its retained descriptor available for disabled readback.
	idleRemainder := func() bool {
		if kind != "extra-tpg" {
			return lioBackendCheck(backend.tpg, "enable", "0") == nil
		}
		if _, err := os.Stat(tpg); !errors.Is(err, os.ErrNotExist) || lioBackendCheck(foreign, "enable", "0") != nil {
			return false
		}
		removedTPG, retainedTarget := false, false
		for _, entry := range backend.entries {
			if entry.name == "tpgt_1" {
				removedTPG = entry.removed
			}
			if entry.name == backend.target.Name {
				retainedTarget = !entry.removed
			}
		}
		return removedTPG && retainedTarget
	}
	if !errors.Is(owner.observe(ctx), ErrReview) || owner.phase != writableReview || owner.released ||
		backend.stops != 1 || !backend.liveAtStop || !backend.stopAttempted || backend.stopped || backend.checkEntries() != nil ||
		!idleRemainder() || owner.policy == nil || owner.credentials == nil {
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
	// No login/backing is added. The extra portal is guest loopback only;
	// the extra TPG stays default-disabled with no portal. Owner's one stop
	// verified idle state before partial removal. Independently remove ONLY
	// the controller's still-witnessed object, never reset/retry backend stop.
	if !idleRemainder() || os.Remove(path) != nil || qemuLIORemoveRemainingFixture(ctx, backend.lioBackend) != nil {
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

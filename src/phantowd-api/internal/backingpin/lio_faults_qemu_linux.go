//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

// Real configfs EEXIST before mutation / after first LUN binding. The backend
// must not adopt or delete the foreign object; failed setup is never success.
func qemuLIOSetupCollision(ctx context.Context, owner *writableOwner, backend *qemuLIOTargetBackend, kind string, paths []string) error {
	var foreignPath string
	switch kind {
	case "existing-target":
		foreignPath = lioCredentialFixtureTarget
	case "existing-second-storage":
		foreignPath = "/sys/kernel/config/target/core/fileio_0/phantowd-fixture-target-7"
	default:
		return ErrInvalid
	}
	if os.Mkdir(foreignPath, 0755) != nil {
		return ErrUnavailable
	}
	foreign, err := os.Open(foreignPath)
	if err != nil {
		return ErrUnavailable
	}
	defer foreign.Close()
	identity, err := lioConfigIdentity(foreign, true)
	if err != nil {
		return err
	}
	if !errors.Is(owner.start(ctx), ErrReview) || owner.phase != writableReview || !owner.released ||
		backend.stops != 1 || !backend.liveAtStop || !backend.stopped || owner.policy != nil || owner.credentials != nil {
		return ErrReview
	}
	if kind == "existing-second-storage" && (!backend.started || len(backend.storages) != 1 || len(backend.luns) != 1) {
		return ErrReview // The fault must occur AFTER actual first-LUN setup.
	}
	if kind == "existing-target" && (backend.prepared || backend.started || len(backend.entries) != 0) {
		return ErrReview
	}
	for _, member := range owner.group {
		if member.file != nil || !member.pin.closed {
			return ErrReview
		}
	}
	for _, peer := range backend.peers {
		if _, err := peer.Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
			return ErrReview
		}
	}
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, make([]byte, 4096*(i+1))) {
			return ErrReview
		}
	}
	if kind == "existing-second-storage" {
		if _, err := os.Stat(lioCredentialFixtureTarget); !errors.Is(err, os.ErrNotExist) {
			return ErrReview
		}
	}
	if observed, err := lioConfigIdentity(foreign, true); err != nil || observed != identity {
		return ErrReview
	}
	current, err := os.Open(foreignPath)
	if err != nil {
		return ErrReview
	}
	observed, observeErr := lioConfigIdentity(current, true)
	closeErr := current.Close()
	if observeErr != nil || closeErr != nil || observed != identity {
		return ErrReview
	}
	for _, operation := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(operation(), ErrReview) {
			return ErrReview
		}
	}
	if backend.stops != 1 || os.Remove(foreignPath) != nil {
		return ErrReview // Independent fixture owner removes only its foreign NEW object.
	}
	return nil
}

// Real referenced-object refusal during reverse teardown, after earlier owned
// objects have already been removed. A separate NEW test-only LUN holds the
// storage reference; it is deliberately unowned by the backend. Exclusive
// configfs mutation authority is still a product gate.
func qemuLIOPartialDelete(ctx context.Context, owner *writableOwner, backend *qemuLIOTargetBackend,
	policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, lease *mountowner.MountedVolumeSetLease) error {
	const name = "foreign-blocker"
	destination := backend.storages[0]
	// Regression for the original invalid fault trigger: a LUN can bind only
	// one device. A second link on an already-bound LUN must fail with EEXIST.
	if err := unix.Symlinkat(fmt.Sprintf("/proc/self/fd/%d", destination.Fd()), int(backend.luns[0].Fd()), name); !errors.Is(err, unix.EEXIST) {
		return ErrReview
	}
	var absent unix.Stat_t
	if err := unix.Fstatat(int(backend.luns[0].Fd()), name, &absent, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return ErrReview
	}
	const foreignPath = lioCredentialFixtureTarget + "/tpgt_1/lun/lun_8"
	if os.Mkdir(foreignPath, 0755) != nil {
		return ErrUnavailable
	}
	parent, err := os.Open(foreignPath)
	if err != nil {
		return ErrUnavailable
	}
	defer parent.Close()
	parentID, err := lioConfigIdentity(parent, true)
	if err != nil {
		return err
	}
	destinationID, err := lioConfigIdentity(destination, true)
	if err != nil || destinationID.mount != parentID.mount {
		return ErrReview
	}
	if unix.Symlinkat(fmt.Sprintf("/proc/self/fd/%d", destination.Fd()), int(parent.Fd()), name) != nil {
		return ErrUnavailable
	}
	var witness unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &witness, unix.AT_SYMLINK_NOFOLLOW) != nil || witness.Mode&unix.S_IFMT != unix.S_IFLNK || witness.Uid != 0 {
		return ErrReview
	}
	if !errors.Is(owner.stop(ctx), ErrReview) || backend.stops != 1 || !backend.liveAtStop || !backend.stopAttempted || backend.stopped ||
		owner.phase != writableReview || owner.released || owner.policy == nil || owner.credentials == nil ||
		backend.checkEntries() != nil || backend.sink.verifyDisabled(ctx) != nil || !qemuLIOSessionState(backend.lioBackend, true) {
		return ErrReview
	}
	removed, remaining := 0, 0
	for _, entry := range backend.entries {
		if entry.removed {
			removed++
		} else {
			remaining++
		}
	}
	if removed == 0 || remaining == 0 || !errors.Is(policy.Close(), naspolicystore.ErrBusy) ||
		!errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
		return ErrReview
	}
	for _, member := range owner.group {
		if member.file == nil || member.pin.consumer != owner || !errors.Is(member.pin.Close(), ErrBusy) {
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
	var current unix.Stat_t
	if backend.stops != 1 || unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		current.Ino != witness.Ino || current.Mode != witness.Mode || current.Uid != witness.Uid {
		return ErrReview
	}
	if observed, err := lioConfigIdentity(parent, true); err != nil || observed != parentID {
		return ErrReview
	}
	if observed, err := lioConfigIdentity(destination, true); err != nil || observed != destinationID {
		return ErrReview
	}
	currentParent, err := os.Open(foreignPath)
	if err != nil {
		return ErrReview
	}
	observed, observeErr := lioConfigIdentity(currentParent, true)
	closeErr := currentParent.Close()
	if observeErr != nil || closeErr != nil || observed != parentID {
		return ErrReview
	}
	// Independent test controller, not backend retry/recovery: remove only its
	// still-witnessed blocker, then dispose remaining idle owned fixture objects.
	if unix.Unlinkat(int(parent.Fd()), name, 0) != nil || os.Remove(foreignPath) != nil || backend.checkEntries() != nil ||
		backend.sink.verifyDisabled(ctx) != nil || !qemuLIOSessionState(backend.lioBackend, true) ||
		qemuLIORemoveRemainingFixture(ctx, backend.lioBackend) != nil {
		return ErrReview
	}
	owner.mu.Lock()
	err = owner.releaseLocked()
	owner.mu.Unlock()
	if err != nil || backend.stops != 1 || !backend.stopAttempted || backend.stopped || owner.phase != writableReview {
		return ErrReview
	}
	return nil
}

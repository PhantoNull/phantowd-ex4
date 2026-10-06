// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
)

// DisableForFileService explicitly revokes one account using the backend fixed
// at Owner Open. It replaces a backend-bound consumer only after a complete,
// non-recovering before/after observation qualifies exactly that transition.
// The old token never revives. On uncertainty it stays retained in review and
// no successor is returned; callers must independently stop before releasing.
// This internal operation neither starts nor supervises a product service.
func (op *SMBOperation) DisableForFileService(ctx context.Context, expected uint64, current *FileServiceLease) (*FileServiceLease, error) {
	if op == nil || op.owner == nil || current == nil || current.state == nil {
		return nil, ErrInvalid
	}
	o := op.owner
	if current.state.owner != o {
		return nil, ErrConflict
	}
	if err := o.enter(ctx); err != nil {
		return nil, err
	}
	defer o.mu.Unlock()
	state := current.state
	if state.released {
		return nil, ErrUnavailable
	}
	if state.review {
		return nil, ErrReview
	}
	if _, retained := o.fileServiceLeases[state]; !retained {
		state.review = true
		return nil, ErrReview
	}
	if !sameSMBBackend(o.smbBackend, state.smbBackend) {
		return nil, ErrConflict
	}
	before, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil || ctx.Err() != nil || before.Fingerprint != state.fingerprint {
		state.review = true
		return nil, errors.Join(ErrReview, err)
	}
	var target smbprovision.Journal
	for _, entry := range before.Samba {
		if entry.Journal.Account.ID == op.id {
			target = entry.Journal
			break
		}
	}
	if target.Revision != expected || target.Account.ID == "" {
		return nil, smbprovision.ErrConflict
	}
	if target.Phase != smbprovision.Enabled || expected > ^uint64(0)-2 {
		return nil, smbprovision.ErrInvalid
	}
	store := o.smbJournals[op.id]
	if store == nil {
		state.review = true
		return nil, ErrReview
	}
	journal, err := store.Load()
	if err != nil || journal != target {
		state.review = true
		return nil, errors.Join(ErrReview, o.smbFailure(err))
	}
	if err := o.verifyUnixLocked(ctx, target.Account); err != nil {
		state.review = true
		return nil, errors.Join(ErrReview, err)
	}
	// Invalidate before any intent/worker can run. Keep the original consumer
	// reference throughout the mutation and all postconditions, including errors.
	state.review = true
	if err := store.Disable(ctx, expected); err != nil {
		return nil, errors.Join(ErrReview, o.smbFailure(err))
	}
	after, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil || ctx.Err() != nil || !onlySMBDisableChanged(before, after, op.id) {
		return nil, errors.Join(ErrReview, err)
	}
	if ctx.Err() != nil {
		return nil, ErrReview
	}
	successor := &fileServiceLeaseState{owner: o, fingerprint: after.Fingerprint, smbBackend: state.smbBackend}
	// Transfer the bounded slot under the SAME lock. There is no externally
	// observable zero-consumer interval, even at the common capacity of sixteen.
	delete(o.fileServiceLeases, state)
	o.fileServiceLeases[successor] = struct{}{}
	return &FileServiceLease{state: successor}, nil
}

// Compare all private evidence, not only target SID or a fresh arbitrary hash.
// Work on copied slices so no caller/retained observation is amended in place.
func onlySMBDisableChanged(before, after FileServiceSnapshot, id string) bool {
	expected := before
	expected.Samba = append([]FileServiceSamba(nil), before.Samba...)
	expected.Passdb = append([]FileServicePassdb(nil), before.Passdb...)
	journalFound, passdbFound := false, false
	for i := range expected.Samba {
		entry := &expected.Samba[i]
		if entry.Journal.Account.ID != id {
			continue
		}
		if journalFound || entry.Journal.Phase != smbprovision.Enabled || entry.Observation.Disabled ||
			entry.Journal.Revision > ^uint64(0)-2 {
			return false
		}
		entry.Journal.Phase = smbprovision.Disabled
		entry.Journal.Revision += 2
		entry.Observation.Disabled = true
		journalFound = true
	}
	for i := range expected.Passdb {
		entry := &expected.Passdb[i]
		if entry.AccountID != id {
			continue
		}
		if passdbFound || !entry.Observation.Present || entry.Observation.Disabled {
			return false
		}
		entry.Observation.Disabled = true
		passdbFound = true
	}
	// Fingerprints must change, but are not a substitute for exact delta checks.
	if !journalFound || !passdbFound || before.Fingerprint == after.Fingerprint || after.Fingerprint == ([32]byte{}) {
		return false
	}
	expected.Fingerprint, after.Fingerprint = [32]byte{}, [32]byte{}
	return reflect.DeepEqual(expected, after)
}

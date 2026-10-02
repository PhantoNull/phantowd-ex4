//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"os"
	"sync"
)

// MountedVolumeSetLease retains one lease for every member of a fixed mounted
// volume roster. It is process-local authority and cannot be serialized.
type MountedVolumeSetLease struct {
	mu       sync.Mutex
	closed   bool
	set      *MountedVolumeSet
	evidence MountedVolumeSetEvidence
	leases   map[string]*Lease
	ordered  []*Lease
}

// Acquire atomically observes the complete fixed roster and retains a lease
// on every member before releasing any Owner lock. On every failure it rolls
// back acquired child leases and never returns partial authority.
func (s *MountedVolumeSet) Acquire(ctx context.Context) (*MountedVolumeSetLease, MountedVolumeSetEvidence, error) {
	if s == nil || ctx == nil {
		return nil, MountedVolumeSetEvidence{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, owner := range s.lockOrder {
		owner.mu.Lock()
	}
	defer func() {
		for index := len(s.lockOrder) - 1; index >= 0; index-- {
			s.lockOrder[index].mu.Unlock()
		}
	}()

	if ctx.Err() != nil {
		return nil, MountedVolumeSetEvidence{}, ErrUnavailable
	}
	evidence, err := s.observeLocked()
	if err != nil {
		return nil, MountedVolumeSetEvidence{}, err
	}
	result := &MountedVolumeSetLease{
		set: s, evidence: evidence, leases: make(map[string]*Lease, len(s.members)),
		ordered: make([]*Lease, 0, len(s.members)),
	}
	for _, member := range s.members {
		if ctx.Err() != nil {
			err = ErrUnavailable
		} else {
			var child *Lease
			child, err = member.owner.acquireLocked(ctx)
			if err == nil {
				result.leases[member.volumeID] = child
				result.ordered = append(result.ordered, child)
				continue
			}
		}
		if rollbackErr := result.rollbackLocked(); rollbackErr != nil {
			return nil, MountedVolumeSetEvidence{}, errors.Join(err, rollbackErr)
		}
		return nil, MountedVolumeSetEvidence{}, err
	}
	return result, evidence, nil
}

// Verify revalidates every member of the exact roster while all Owner locks
// are held. It succeeds only while the complete evidence remains identical to
// the evidence captured when this lease was issued. It opens no descriptors
// and never repairs, releases or reacquires authority.
func (l *MountedVolumeSetLease) Verify() (MountedVolumeSetEvidence, error) {
	if l == nil || l.set == nil {
		return MountedVolumeSetEvidence{}, ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return MountedVolumeSetEvidence{}, ErrUnavailable
	}
	s := l.set
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, owner := range s.lockOrder {
		owner.mu.Lock()
	}
	defer func() {
		for index := len(s.lockOrder) - 1; index >= 0; index-- {
			s.lockOrder[index].mu.Unlock()
		}
	}()

	evidence, err := s.observeLocked()
	if err != nil {
		return MountedVolumeSetEvidence{}, err
	}
	if evidence.generation != l.evidence.generation || evidence.fingerprint != l.evidence.fingerprint ||
		len(l.ordered) != len(s.members) {
		return MountedVolumeSetEvidence{}, ErrReview
	}
	for _, member := range s.members {
		child := l.leases[member.volumeID]
		if child == nil || child.closed {
			return MountedVolumeSetEvidence{}, ErrUnavailable
		}
		if _, active := member.owner.leases[child]; !active {
			return MountedVolumeSetEvidence{}, ErrUnavailable
		}
	}
	return evidence, nil
}

// rollbackLocked requires all Owners in set.lockOrder to be locked.
func (l *MountedVolumeSetLease) rollbackLocked() error {
	if l == nil || l.set == nil {
		return nil
	}
	var result error
	for index := len(l.ordered) - 1; index >= 0; index-- {
		child := l.ordered[index]
		if err := child.closeLocked(); err != nil {
			result = errors.Join(result, ErrReview)
			_ = child.owner.reviewLocked()
		}
	}
	return result
}

// OpenDirectory resolves a directory only through the lease for its
// canonical roster member. Unknown members and a closed group are rejected.
func (l *MountedVolumeSetLease) OpenDirectory(volumeID, relative string) (*os.File, error) {
	if l == nil {
		return nil, ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, ErrUnavailable
	}
	child := l.leases[volumeID]
	if child == nil {
		return nil, ErrInvalid
	}
	return child.OpenDirectory(relative)
}

// Close releases all child leases in canonical roster order. It is
// idempotent; uncertainty closing any tracked descriptor quarantines that
// member and never triggers a retry or automatic remount.
func (l *MountedVolumeSetLease) Close() error {
	if l == nil || l.set == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	for _, owner := range l.set.lockOrder {
		owner.mu.Lock()
	}
	defer func() {
		for index := len(l.set.lockOrder) - 1; index >= 0; index-- {
			l.set.lockOrder[index].mu.Unlock()
		}
	}()

	var result error
	for index, child := range l.ordered {
		if err := child.closeLocked(); err != nil {
			_ = child.owner.reviewLocked()
			result = errors.Join(result, ErrReview)
		}
		l.ordered[index] = nil
	}
	l.leases = nil
	l.closed = true
	return result
}

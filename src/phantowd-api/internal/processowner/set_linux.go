//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
)

const maxSetMembers = 8

type setMember struct {
	name     string
	spec     Spec
	owner    *Owner
	snapshot Snapshot
}

// Set owns a fixed, ordered collection of foreground processes. It provides
// all-ready startup with reverse-order rollback; it is not a product service
// manager, persistent owner, or automatic recovery mechanism.
type Set struct {
	gate           chan struct{}
	state          State
	generation     uint64
	reviewRequired bool
	members        []setMember
}

// NewSet validates and copies fixed service launch specifications. It starts
// no process. Names and specifications are internal construction inputs, not
// runtime or network selection.
func NewSet(specs []MemberSpec) (*Set, error) {
	if len(specs) == 0 || len(specs) > maxSetMembers {
		return nil, ErrInvalid
	}
	set := &Set{gate: make(chan struct{}, 1), state: StateStopped,
		members: make([]setMember, 0, len(specs))}
	names := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if !validMemberName(spec.Name) || validateSpec(spec.Process) != nil {
			return nil, ErrInvalid
		}
		if _, exists := names[spec.Name]; exists {
			return nil, ErrInvalid
		}
		names[spec.Name] = struct{}{}
		process := spec.Process
		process.Args = append([]string(nil), process.Args...)
		set.members = append(set.members, setMember{
			name: spec.Name, spec: process, owner: New(),
			snapshot: Snapshot{State: StateStopped},
		})
	}
	return set, nil
}

// Start brings members up in declaration order. The set is reported ready and
// advances generation only after every member passes its readiness probe. A
// clean failure rolls already-ready members back in reverse order; any
// uncertain member or rollback result permanently requires review.
func (s *Set) Start(ctx context.Context) (SetSnapshot, error) {
	if err := s.enter(ctx); err != nil {
		return SetSnapshot{}, err
	}
	defer s.leave()
	if s.reviewRequired {
		return s.snapshot(), ErrReviewRequired
	}
	if s.state == StateReady {
		return s.snapshot(), ErrAlreadyRunning
	}
	if s.state != StateStopped {
		return s.snapshot(), ErrUnavailable
	}

	s.state = StateStarting
	started := make([]int, 0, len(s.members))
	for index := range s.members {
		member := &s.members[index]
		observed, err := member.owner.Start(ctx, member.spec)
		member.snapshot = observed
		if err == nil {
			started = append(started, index)
			continue
		}

		rollbackErr := s.rollback(started)
		if errors.Is(err, ErrReviewRequired) || rollbackErr != nil {
			s.reviewRequired = true
			s.state = StateReviewRequired
			return s.snapshot(), errors.Join(
				fmt.Errorf("service %q failed to start: %w", member.name, err),
				ErrReviewRequired,
				rollbackErr,
			)
		}
		s.state = StateStopped
		return s.snapshot(), fmt.Errorf("service %q failed to start: %w", member.name, err)
	}
	s.generation++
	s.state = StateReady
	return s.snapshot(), nil
}

// Observe checks every member without restarting or stopping any process. An
// unexpected member exit quarantines the set and blocks another Start; healthy
// peers remain untouched for an explicit caller decision.
func (s *Set) Observe(ctx context.Context) (SetSnapshot, error) {
	if err := s.enter(ctx); err != nil {
		return SetSnapshot{}, err
	}
	defer s.leave()
	var review bool
	for index := range s.members {
		member := &s.members[index]
		observed, err := member.owner.Observe(ctx)
		member.snapshot = observed
		if errors.Is(err, ErrReviewRequired) {
			review = true
			continue
		}
		if err != nil {
			return s.snapshot(), err
		}
	}
	if review {
		s.reviewRequired = true
		s.state = StateReviewRequired
		return s.snapshot(), ErrReviewRequired
	}
	if s.reviewRequired {
		return s.snapshot(), ErrReviewRequired
	}
	return s.snapshot(), nil
}

// Stop attempts cleanup for every member in reverse declaration order. It
// continues after a member requires review so unrelated owned process groups
// still receive their one bounded stop attempt. Review is never cleared.
func (s *Set) Stop(ctx context.Context) (SetSnapshot, error) {
	if ctx == nil || s == nil || s.gate == nil {
		return SetSnapshot{}, ErrUnavailable
	}
	if err := s.enter(context.Background()); err != nil {
		return SetSnapshot{}, err
	}
	defer s.leave()
	wasReviewRequired := s.reviewRequired
	s.state = StateStopping
	for index := len(s.members) - 1; index >= 0; index-- {
		member := &s.members[index]
		observed, err := member.owner.Stop(context.Background())
		member.snapshot = observed
		if err != nil {
			wasReviewRequired = true
		}
	}
	if wasReviewRequired {
		s.reviewRequired = true
		s.state = StateReviewRequired
		return s.snapshot(), ErrReviewRequired
	}
	s.state = StateStopped
	return s.snapshot(), nil
}

func (s *Set) rollback(started []int) error {
	var rollbackErr error
	for index := len(started) - 1; index >= 0; index-- {
		member := &s.members[started[index]]
		observed, err := member.owner.Stop(context.Background())
		member.snapshot = observed
		if err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("service %q rollback requires review: %w", member.name, err))
		}
	}
	return rollbackErr
}

func (s *Set) enter(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.gate == nil {
		return ErrUnavailable
	}
	select {
	case s.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	if ctx.Err() != nil {
		<-s.gate
		return ErrUnavailable
	}
	return nil
}

func (s *Set) leave() { <-s.gate }

func (s *Set) snapshot() SetSnapshot {
	result := SetSnapshot{State: s.state, Generation: s.generation,
		Members: make([]MemberSnapshot, len(s.members))}
	for index, member := range s.members {
		result.Members[index] = MemberSnapshot{Name: member.name, Process: member.snapshot}
	}
	return result
}

func validMemberName(name string) bool {
	if len(name) == 0 || len(name) > 32 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for index := 1; index < len(name); index++ {
		c := name[index]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

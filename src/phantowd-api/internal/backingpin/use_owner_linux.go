//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
)

// One trusted composition supplies the SAME authority to all its consumers.
// This is cooperative in-process exclusion, not a filesystem lock, external-use
// census or cross-protocol/product authority. No paths, caller-provided inode
// tuples or serialized claims are accepted. Zero values are not initialized.
type backingUseOwner struct {
	nonSerializable
	mu             sync.Mutex
	entries        map[backingObject]*backingUseLease
	closed, review bool
}

type backingObject struct {
	major, minor uint32
	inode        uint64 // Mount/VolumeID/path deliberately cannot hide bind aliases.
}

type backingUseLease struct {
	nonSerializable
	source   *backingUseOwner
	consumer *writableOwner
	objects  []backingObject
	released bool // Requires source.mu, never independently mutable by callers.
}

func newBackingUseOwner() *backingUseOwner {
	return &backingUseOwner{entries: make(map[backingObject]*backingUseLease)}
}

// The consumer already privately holds its Pins/files. Observe each actual RW
// descriptor against its retained Pin under ONE Pin lock at a time, then reserve
// the entire immutable roster atomically. No I/O or other lock under source.mu.
// Lock order during lifecycle: consumer -> individual Pin; separately consumer
// -> use authority. Authority NEVER calls back into consumer, Pin or sources.
func (s *backingUseOwner) acquire(o *writableOwner) (*backingUseLease, error) {
	if s == nil || o == nil || o.use != nil {
		return nil, ErrInvalid
	}
	members := o.group
	if len(members) == 0 {
		members = []targetBacking{{pin: o.pin, file: o.file}}
	}
	if len(members) > iscsipolicy.MaxLUNs {
		return nil, ErrInvalid
	}
	objects := make([]backingObject, 0, len(members))
	seen := make(map[backingObject]bool, len(members))
	for _, member := range members {
		if member.pin == nil || member.file == nil {
			return nil, ErrInvalid
		}
		p := member.pin
		p.mu.Lock()
		probe := &writableOwner{pin: p, file: member.file}
		valid := p.consumer == o && probe.checkDescriptorLocked() == nil
		id := p.fileIdentity
		p.mu.Unlock()
		if !valid || id.inode == 0 {
			return nil, ErrUnavailable
		}
		key := backingObject{id.major, id.minor, id.inode}
		if seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		objects = append(objects, key)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		return nil, ErrInvalid
	}
	if s.review {
		return nil, ErrReview
	}
	if s.closed {
		return nil, ErrClosed
	}
	for _, key := range objects {
		if s.entries[key] != nil {
			return nil, ErrBusy // No earlier member is published on later conflict.
		}
	}
	if len(s.entries)+len(objects) > iscsipolicy.MaxBackings {
		return nil, ErrBusy
	}
	l := &backingUseLease{source: s, consumer: o, objects: objects}
	for _, key := range objects {
		s.entries[key] = l
	}
	return l, nil
}

func (l *backingUseLease) verifyLocked() error {
	s := l.source
	if s.review || s.closed || l.released || l.consumer == nil || len(l.objects) == 0 {
		return ErrReview
	}
	for _, key := range l.objects {
		if s.entries[key] != l {
			s.review = true
			return ErrReview
		}
	}
	return nil
}

func (l *backingUseLease) verify() error {
	if l == nil || l.source == nil {
		return ErrReview
	}
	l.source.mu.Lock()
	defer l.source.mu.Unlock()
	return l.verifyLocked()
}

// Only the containing lifecycle releases after verified whole-backend stop,
// all descriptor/Pin closures and source releases. Failed admission may release
// its unpublished reservation while returning all original caller resources.
func (l *backingUseLease) release() error {
	if l == nil || l.source == nil {
		return ErrReview
	}
	s := l.source
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.released {
		return nil
	}
	if err := l.verifyLocked(); err != nil {
		return err
	}
	for _, key := range l.objects {
		delete(s.entries, key)
	}
	l.released, l.consumer, l.objects = true, nil, nil
	return nil
}

func (s *backingUseOwner) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		return ErrInvalid
	}
	if s.review {
		return ErrReview
	}
	if len(s.entries) != 0 {
		return ErrBusy
	}
	s.closed = true
	return nil
}

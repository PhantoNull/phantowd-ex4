//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"io/fs"
	"os"
	"strings"
	"sync"
)

type rootPinNonSerializable struct{}

func (rootPinNonSerializable) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*rootPinNonSerializable) UnmarshalJSON([]byte) error  { return ErrUnavailable }

// VolumeRootPin retains the existing complete roster lease for one member.
// OpenDirectory returns independent caller-owned O_PATH descriptors, unlike
// the original lease's Owner-tracked handles. Close those descriptors before
// Release. No data opener, raw Root export, global-use or writable admission.
// Lock order: pin -> group lease -> set -> canonical member Owners.
type VolumeRootPin struct {
	rootPinNonSerializable
	mu             sync.Mutex
	lease          *MountedVolumeSetLease
	volumeID       string
	closed, review bool
	uncertain      bool
}

func (l *MountedVolumeSetLease) PinVolumeRoot(volumeID string) (*VolumeRootPin, error) {
	if l == nil || l.set == nil || !validVolumeID(volumeID) {
		return nil, ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, ErrUnavailable
	}
	if l.leases[volumeID] == nil {
		return nil, ErrInvalid
	}
	if _, err := l.verifyLocked(); err != nil {
		return nil, err
	}
	pin := &VolumeRootPin{lease: l, volumeID: volumeID}
	if l.rootPins == nil {
		l.rootPins = make(map[*VolumeRootPin]struct{})
	}
	l.rootPins[pin] = struct{}{}
	return pin, nil
}

func (p *VolumeRootPin) Verify() error {
	if p == nil || p.lease == nil {
		return ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := p.availableLocked(); err != nil {
		return err
	}
	if _, err := l.verifyLocked(); err != nil {
		p.review = true
		return ErrReview
	}
	return nil
}

// No Owner-tracked handle is registered here. Repeated verification/open/close
// cannot accumulate tracked descriptors or double-close them on lease release.
// This still performs metadata I/O; there is no universal syscall deadline.
func (p *VolumeRootPin) OpenDirectory(relative string) (*os.File, error) {
	if p == nil || p.lease == nil {
		return nil, ErrUnavailable
	}
	if !fs.ValidPath(relative) || len(relative) > 1024 || strings.ContainsAny(relative, "\\\x00") {
		return nil, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := p.availableLocked(); err != nil {
		return nil, err
	}
	unlock := l.lockOwnersLocked()
	defer unlock()
	if _, err := l.verifyOwnersLocked(); err != nil {
		p.review = true
		return nil, ErrReview
	}
	child := l.leases[p.volumeID]
	if child == nil || child.owner.root == nil {
		p.review = true
		return nil, ErrReview
	}
	file, openErr := child.owner.root.OpenDirectory(relative)
	_, verifyErr := l.verifyOwnersLocked()
	if openErr != nil || file == nil || verifyErr != nil {
		p.review = true
		if file != nil {
			if file.Close() != nil {
				p.uncertain = true
			}
		}
		return nil, ErrReview
	}
	return file, nil
}

// Release drops only this lease pin, never closes caller-owned descriptors or
// releases/unmounts the original group. The owning consumer must stop and close
// every descendant reference first. backingpin keeps this token private.
func (p *VolumeRootPin) Release() error {
	if p == nil || p.lease == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.uncertain {
		return ErrReview
	}
	l := p.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.rootPins[p]; !exists || l.closed {
		p.review = true
		return ErrReview
	}
	delete(l.rootPins, p)
	p.closed = true
	return nil
}

// Requires p.mu and p.lease.mu. Observed failure is sticky, including complete
// roster drift outside the selected member; restoration does not revive a pin.
func (p *VolumeRootPin) availableLocked() error {
	if p.closed {
		return ErrUnavailable
	}
	if p.review {
		return ErrReview
	}
	if _, exists := p.lease.rootPins[p]; !exists || p.lease.closed {
		p.review = true
		return ErrReview
	}
	return nil
}

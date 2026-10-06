// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import "context"

const maxFileServiceLeases = 16

// FileServiceLease cooperatively retains this exact Owner's authority, not
// mutable passdb bytes or a daemon configuration. The consumer must verify and
// stop all descendants before Release; this token does not supervise a service.
// Copies share one private state, serialized only by the original Owner lock.
type FileServiceLease struct {
	state *fileServiceLeaseState
}

type fileServiceLeaseState struct {
	owner       *Owner
	fingerprint [32]byte
	released    bool
	review      bool
}

// RetainFileServiceSnapshot re-observes complete evidence under the Owner lock
// and retains only an exact expected fingerprint from a trusted prior snapshot.
// It does not run inside WithFileServiceSnapshot's pure callback or expose I/O,
// credentials, a filesystem path, or activation through that callback.
func (o *Owner) RetainFileServiceSnapshot(ctx context.Context, expected [32]byte) (*FileServiceLease, error) {
	if expected == ([32]byte{}) {
		return nil, ErrInvalid
	}
	if err := o.enter(ctx); err != nil {
		return nil, err
	}
	defer o.mu.Unlock()
	if len(o.fileServiceLeases) >= maxFileServiceLeases {
		return nil, ErrBusy
	}
	evidence, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil {
		return nil, err
	}
	if evidence.Fingerprint != expected {
		return nil, ErrConflict
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	state := &fileServiceLeaseState{owner: o, fingerprint: expected}
	if o.fileServiceLeases == nil {
		o.fileServiceLeases = make(map[*fileServiceLeaseState]struct{})
	}
	o.fileServiceLeases[state] = struct{}{}
	return &FileServiceLease{state: state}, nil
}

func (l *FileServiceLease) Verify(ctx context.Context) error {
	if l == nil || l.state == nil || l.state.owner == nil {
		return ErrUnavailable
	}
	o := l.state.owner
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if l.state.released {
		return ErrUnavailable
	}
	if l.state.review {
		return ErrReview
	}
	if _, retained := o.fileServiceLeases[l.state]; !retained {
		l.state.review = true
		return ErrReview
	}
	evidence, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil || ctx.Err() != nil || evidence.Fingerprint != l.state.fingerprint {
		l.state.review = true
		return ErrReview
	}
	return nil
}

// Release only drops the cooperative consumer reference. It closes no input
// or process, never releases the original Owner, and remains usable after drift
// so a trusted coordinator can release following independently verified stop.
func (l *FileServiceLease) Release() error {
	if l == nil || l.state == nil || l.state.owner == nil {
		return nil
	}
	o := l.state.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.state.released {
		return nil
	}
	delete(o.fileServiceLeases, l.state)
	l.state.released = true
	return nil
}

func (FileServiceLease) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*FileServiceLease) UnmarshalJSON([]byte) error  { return ErrUnavailable }

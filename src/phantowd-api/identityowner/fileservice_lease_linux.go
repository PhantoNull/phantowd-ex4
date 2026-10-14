// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
)

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
	smbBackend  smbprovision.Backend
	released    bool
	review      bool
}

// RetainFileServiceSnapshot re-observes complete evidence under the Owner lock
// and retains only an exact expected fingerprint from a trusted prior snapshot.
// It does not run inside WithFileServiceSnapshot's pure callback or expose I/O,
// credentials, a filesystem path, or activation through that callback.
func (o *Owner) RetainFileServiceSnapshot(ctx context.Context, expected [32]byte) (*FileServiceLease, error) {
	return o.retainFileServiceSnapshot(ctx, expected, nil)
}

// RetainSMBFileServiceSnapshot additionally requires the exact non-nil pointer
// backend already fixed by OpenWithSMBBackend. The argument is only an identity
// assertion: observations always use the Owner's backend, never the supplied
// candidate. It neither substitutes an executor nor authorizes daemon startup.
// Value adapters and zero-sized pointees cannot establish unique object identity.
// Call outside Owner/runtime gates; Verify reads passdb under the Owner lock.
func (o *Owner) RetainSMBFileServiceSnapshot(ctx context.Context, expected [32]byte, backend smbprovision.Backend) (*FileServiceLease, error) {
	if !sameSMBBackend(backend, backend) {
		return nil, ErrInvalid
	}
	return o.retainFileServiceSnapshot(ctx, expected, backend)
}

func sameSMBBackend(actual, expected smbprovision.Backend) bool {
	a, e := reflect.ValueOf(actual), reflect.ValueOf(expected)
	return a.IsValid() && e.IsValid() && a.Kind() == reflect.Pointer && e.Kind() == reflect.Pointer &&
		!a.IsNil() && !e.IsNil() && a.Type() == e.Type() && a.Type().Elem().Size() != 0 && actual == expected
}

func (o *Owner) retainFileServiceSnapshot(ctx context.Context, expected [32]byte, backend smbprovision.Backend) (*FileServiceLease, error) {
	if expected == ([32]byte{}) {
		return nil, ErrInvalid
	}
	if err := o.enter(ctx); err != nil {
		return nil, err
	}
	defer o.mu.Unlock()
	if backend != nil && !sameSMBBackend(o.smbBackend, backend) {
		return nil, ErrConflict
	}
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
	state := &fileServiceLeaseState{owner: o, fingerprint: expected, smbBackend: backend}
	if o.fileServiceLeases == nil {
		o.fileServiceLeases = make(map[*fileServiceLeaseState]struct{})
	}
	o.fileServiceLeases[state] = struct{}{}
	return &FileServiceLease{state: state}, nil
}

func (l *FileServiceLease) Verify(ctx context.Context) error {
	return l.WithFileServiceSnapshot(ctx, func(FileServiceSnapshot) error { return nil })
}

// WithFileServiceSnapshot derives bounded in-memory data from ONE freshly
// verified retained observation while the original mutation lock is held.
// The callback has the same pure derivation contract as Owner's method: no
// Owner re-entry, process/filesystem/network I/O, persistence or activation.
// It never accepts a replacement Owner, backend or expected fingerprint.
// A pure callback refusal alone does not invalidate healthy identity evidence.
func (l *FileServiceLease) WithFileServiceSnapshot(ctx context.Context, inspect func(FileServiceSnapshot) error) error {
	if inspect == nil || l == nil || l.state == nil || l.state.owner == nil {
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
	if l.state.smbBackend != nil && !sameSMBBackend(o.smbBackend, l.state.smbBackend) {
		l.state.review = true
		return ErrReview
	}
	evidence, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil || ctx.Err() != nil || evidence.Fingerprint != l.state.fingerprint {
		l.state.review = true
		return ErrReview
	}
	err = inspect(evidence)
	if ctx.Err() != nil {
		l.state.review = true
		return ErrReview
	}
	return err
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

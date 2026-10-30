//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

// NASOwnerBootstrap is a separate owner-capable trusted-parent lifetime.
// Ordinary read-only observers never gain an admission or conversion method.
// Confirmation still requires independent base bytes and consumer exclusion;
// matching observations alone grant neither. No product startup is wired here.
type NASOwnerBootstrap struct {
	mu                                       sync.Mutex
	self                                     *NASOwnerBootstrap
	evidence                                 *NASEvidenceAuthority
	backend                                  nasWriterBackend // Fixed at opening; never supplied per operation.
	seen, moved, closed, review, closeFailed bool
}

func OpenNASOwnerBootstrap(ctx context.Context, directory, installation string) (*NASOwnerBootstrap, error) {
	a, err := OpenNASEvidenceAuthority(ctx, directory, installation)
	if a == nil {
		return nil, err
	}
	b := &NASOwnerBootstrap{evidence: a, backend: systemNASWriterBackend(), review: err != nil}
	b.self = b
	return b, err // Preserve any original failed-cleanup authority.
}

func (b *NASOwnerBootstrap) valid() bool { return b != nil && b.self == b && b.evidence != nil }

func (b *NASOwnerBootstrap) state(ctx context.Context) error {
	if b.moved || b.closed {
		return ErrClosed
	}
	if b.review || b.closeFailed {
		return ErrReview
	}
	return ctx.Err()
}

func (b *NASOwnerBootstrap) Observe(ctx context.Context) (NASEvidenceObservation, error) {
	if !b.valid() || ctx == nil {
		return NASEvidenceObservation{}, ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.state(ctx); err != nil {
		return NASEvidenceObservation{}, err
	}
	v, err := b.evidence.Observe(ctx)
	eligible := !v.Pending && ((v.Kind == naspolicyevidence.NoRecordedOperation && v.Roles == 2) || (v.Kind == naspolicyevidence.MatchingLocalRecords && v.Roles == 5))
	if err != nil || !eligible {
		b.review = true
	} else {
		b.seen = true
	}
	return v, err
}

func (b *NASOwnerBootstrap) Confirm(ctx context.Context, known []byte) (*OwnedStore[naspolicy.Config], error) {
	if !b.valid() || ctx == nil {
		return nil, ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.state(ctx); err != nil {
		return nil, err
	}
	if !b.seen {
		return nil, ErrInvalid
	}
	if !validNASWriterInput(b.evidence.installation, known, b.backend) {
		b.review = true
		return nil, ErrInvalid
	}
	r := b.evidence.root
	w := &nasWriter{retention: r, installation: b.evidence.installation, backend: b.backend, stamp: r.initial}
	w.self = w
	if err := w.confirm(ctx, known); err != nil {
		b.review = true
		return nil, err
	}
	b.moved = true                   // Old bootstrap methods cannot close/reuse the Owner's originals.
	return ownNASWriter(ctx, w, nil) // A non-nil error Owner must still be retained.
}

func (b *NASOwnerBootstrap) Close() error {
	if !b.valid() {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.moved {
		return ErrClosed
	}
	if b.closeFailed {
		return ErrReview
	}
	if b.closed {
		return nil
	}
	if b.evidence.Close() != nil {
		b.review, b.closeFailed = true, true
		return ErrReview
	}
	b.closed = true
	return nil
}

func (*NASOwnerBootstrap) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NASOwnerBootstrap) UnmarshalJSON([]byte) error   { return ErrInvalid }

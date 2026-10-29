//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

// OpenConfirmedNASOwner requires separately confirmed exact bytes and trusted
// exclusion of all consumers. It is not product provisioning or boot admission.
// Lock order: Owner.mu, then the writer's retention.mu. No watch is replaced.
func OpenConfirmedNASOwner(ctx context.Context, directory, installation string, confirmed []byte) (*OwnedStore[naspolicy.Config], error) {
	w, openErr := openNASWriter(ctx, directory, installation, confirmed, systemNASWriterBackend())
	if w == nil {
		return nil, openErr
	}
	b := &ownedPolicyBackend[naspolicy.Config]{close: w.Close}
	b.capture = func(ctx context.Context) (naspolicy.Config, policyObservation, error) {
		var zero naspolicy.Config
		r := w.retention
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.review || r.closeFailed {
			return zero, policyObservation{}, ErrReview
		}
		if r.closed {
			return zero, policyObservation{}, ErrClosed
		}
		kind, err := w.refresh(ctx, w.files, "")
		if err != nil || (kind != naspolicyevidence.NoRecordedOperation && kind != naspolicyevidence.MatchingLocalRecords) {
			r.review = true
			return zero, policyObservation{}, ErrReview
		}
		file := w.files["nas-services.json"]
		value, err := naspolicy.Decode(bytes.NewReader(file.data))
		encoded, encodeErr := json.Marshal(value)
		if err != nil || encodeErr != nil || ctx.Err() != nil {
			r.review = true
			return zero, policyObservation{}, ErrReview
		}
		return value, policyObservation{policyStamp(w.stamp), policyStamp(file.stat), sha256.Sum256(encoded), value.Revision}, nil
	}
	b.commit = func(ctx context.Context, expected uint64, next naspolicy.Config) error {
		if next.Validate() != nil || next.Revision != expected+1 {
			return ErrInvalid
		}
		w.retention.mu.Lock()
		base := bytes.Clone(w.files["nas-services.json"].data)
		w.retention.mu.Unlock()
		current, err := naspolicy.Decode(bytes.NewReader(base))
		if err != nil {
			return ErrReview
		}
		if current.Revision != expected {
			return ErrConflict
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return ErrInvalid
		}
		return w.Commit(ctx, base, encoded)
	}
	o := &OwnedStore[naspolicy.Config]{backend: b, watch: -1, leases: make(map[*PolicyLease[naspolicy.Config]]struct{})}
	o.self = o
	if openErr != nil {
		o.review = true
		return o, openErr // Keep uncertain original cleanup reachable.
	}
	_, baseline, err := b.capture(ctx)
	if err != nil {
		o.review = true
		if o.Close() != nil {
			return o, ErrReview
		}
		return nil, ErrReview
	}
	o.baseline = baseline
	return o, nil
}

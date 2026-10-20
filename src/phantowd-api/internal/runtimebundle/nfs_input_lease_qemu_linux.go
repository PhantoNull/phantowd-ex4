//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// NFSInputLeaseQEMU reserves the original complete code/config/state lifetime.
// It exposes no descriptor, process, backend or service-start authority. Storage
// and identity checks must stay OUTSIDE its parent runtime gate.
type NFSInputLeaseQEMU struct {
	original       *NFSInputLeaseQEMU
	gate           chan struct{}
	parent         *NFSInputsQEMU
	closed, review bool
}

// NewNFSInputLeaseQEMU compares the complete immutable definition/evidence at
// construction, never replacing the parent's original candidate. Data equality
// is not provenance: the containing trusted source Owner must retain/revalidate
// its own original policy, identity and mounted-roster authorities separately.
func NewNFSInputLeaseQEMU(ctx context.Context, parent *NFSInputsQEMU, candidate fileserviceplan.NFSv3Candidate) (*NFSInputLeaseQEMU, error) {
	if ctx == nil || !parent.valid() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !parent.candidate.EquivalentTo(candidate) {
		return nil, ErrMismatch
	}
	s, err := parent.code.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer s.leave()
	if s.sourceReserved {
		return nil, processowner.ErrBusy
	}
	if s.review || s.closed || s.configuration == nil || s.state == nil {
		return nil, ErrReviewRequired
	}
	if err := s.revalidate(ctx); err != nil {
		s.review, s.cause = true, err
		return nil, ErrReviewRequired
	}
	o := &NFSInputLeaseQEMU{gate: make(chan struct{}, 1), parent: parent}
	o.original = o
	s.sourceReserved = true
	return o, nil
}

func (o *NFSInputLeaseQEMU) enter(ctx context.Context) error {
	if o == nil || o.original != o || o.gate == nil || !o.parent.valid() || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

func (o *NFSInputLeaseQEMU) Check(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return ErrUnavailable
	}
	s, err := o.parent.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	return o.revalidate(ctx, s)
}

// Both gates are held by the caller. Preserve the first original cause rather
// than replacing it with a later observation or allowing restoration to clear it.
func (o *NFSInputLeaseQEMU) revalidate(ctx context.Context, s *nfsCodeLifetimeQEMU) error {
	if s.review {
		o.review = true
		return ErrReviewRequired
	}
	var err error
	if !s.sourceReserved || s.closed {
		err = ErrMismatch
	} else {
		err = s.revalidate(ctx)
	}
	if err == nil {
		return nil
	}
	o.review = true
	s.review, s.cause = true, err
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrReviewRequired, err)
	}
	return ErrReviewRequired
}

// Close releases an unstarted reservation, not daemon/kernel settlement. A
// future consumer must prohibit release after admission until verified absent.
// Input drift/uncertainty retains this reservation and the original references.
func (o *NFSInputLeaseQEMU) Close() error {
	if err := o.enter(context.Background()); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return nil
	}
	s, err := o.parent.code.enter(context.Background())
	if err != nil {
		return err
	}
	defer s.leave()
	if err := o.revalidate(context.Background(), s); err != nil {
		return err
	}
	s.sourceReserved = false
	o.closed = true
	return nil
}

func (NFSInputLeaseQEMU) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NFSInputLeaseQEMU) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (NFSInputLeaseQEMU) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-input-lease{private}")
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// SourceRuntimeQEMU reserves ORIGINAL export roots and matching runtime inputs.
// Construction starts no consumer and exposes no descriptors. Its one finite
// access campaign is synthetic QEMU only, not policy/identity authority,
// a complete kernel backend, fault-complete settlement or product admission.
type SourceRuntimeQEMU struct {
	original                       *SourceRuntimeQEMU
	gate                           chan struct{}
	roots                          *ExportRootsQEMU
	inputs                         *runtimebundle.NFSInputsQEMU
	policyAuthority                *sourcePolicyAuthority
	lease                          *runtimebundle.NFSInputLeaseQEMU
	access                         *runtimebundle.NFSSourceAccessQEMU
	accessVolume                   *os.File
	accessAttempted, accessSettled bool
	accessServer                   bool
	serverOwner                    *Owner // Retained through every uncertain backend transition.
	closed, review                 bool
	cause                          error
}

type sourceRuntimeConstructionReview struct {
	constructionreview.Marker
	retained *SourceRuntimeQEMU
	cause    error
}

func (*sourceRuntimeConstructionReview) Error() string {
	return "NFS source/runtime construction retains review"
}
func (e *sourceRuntimeConstructionReview) Unwrap() error   { return e.cause }
func (*sourceRuntimeConstructionReview) Is(err error) bool { return err == ErrReviewRequired }

// Lock order: join -> export roots -> storage lease calls (RETURN) -> runtime
// lease/code calls (RETURN) -> storage recheck. No runtime gate is held through
// storage/identity callbacks. This joins existing handles, never reopened paths.
// Before reservation, mismatch/busy/cancellation has no join effects. After any
// uncertain reservation, retain the ORIGINAL construction error and parents.
func NewSourceRuntimeQEMU(ctx context.Context, roots *ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU) (*SourceRuntimeQEMU, error) {
	return newSourceRuntimeQEMU(ctx, roots, inputs, nil)
}

func newSourceRuntimeQEMU(ctx context.Context, roots *ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU, authority *sourcePolicyAuthority) (*SourceRuntimeQEMU, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := roots.enter()
	if err != nil {
		return nil, err
	}
	defer s.leave()
	if s.runtime != nil {
		return nil, ErrBusy
	}
	if s.review || s.closed || s.closeUncertain {
		return nil, ErrReviewRequired
	}
	if err := s.verify(ctx); err != nil {
		s.review = true
		return nil, err
	}
	if authority != nil {
		if err := authority.verify(ctx, s.candidate); err != nil {
			return nil, err // No runtime reservation or borrowed-claim mutation.
		}
	}
	o := &SourceRuntimeQEMU{gate: make(chan struct{}, 1), roots: roots, inputs: inputs, policyAuthority: authority}
	o.original = o
	o.lease, err = runtimebundle.NewNFSInputLeaseQEMU(ctx, inputs, s.candidate)
	if err != nil {
		if !errors.Is(err, runtimebundle.ErrReviewRequired) && !constructionreview.Contains(err) {
			return nil, err // No reservation acquired; never close borrowed parents.
		}
		s.runtime = o
		o.review, o.cause = true, err
		return nil, &sourceRuntimeConstructionReview{retained: o, cause: err}
	}
	s.runtime = o
	if err := o.verify(ctx, s); err != nil {
		o.review = true // A busy post-reservation check must also retain both sides.
		if o.cause == nil {
			o.cause = err
		}
		return nil, &sourceRuntimeConstructionReview{retained: o, cause: o.cause}
	}
	return o, nil
}

func (o *SourceRuntimeQEMU) enter(ctx context.Context) error {
	if o == nil || o.original != o || o.gate == nil || o.roots == nil || o.lease == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

func (o *SourceRuntimeQEMU) fail(err error) error {
	o.review = true
	if o.cause == nil {
		o.cause = err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrReviewRequired, err)
	}
	return ErrReviewRequired
}

// Both join/root gates are held; lower-level gates release before the next
// domain is entered. These sequential checks are NOT atomic service admission.
func (o *SourceRuntimeQEMU) verify(ctx context.Context, s *exportRoots) error {
	if s.runtime != o || s.closed || s.review || s.closeUncertain {
		return o.fail(ErrReviewRequired)
	}
	if err := s.verify(ctx); err != nil {
		s.review = true
		return o.fail(err)
	}
	if o.policyAuthority != nil {
		if err := o.policyAuthority.verify(ctx, s.candidate); err != nil {
			return o.fail(err)
		}
	}
	if err := o.lease.Check(ctx); err != nil {
		if errors.Is(err, processowner.ErrBusy) {
			return ErrBusy
		}
		return o.fail(err)
	}
	if o.accessServer {
		if o.access == nil {
			return o.fail(ErrInvalid)
		}
		if err := o.access.CheckServerFixtureQEMU(ctx); err != nil {
			return o.fail(err)
		}
	}
	if err := s.verify(ctx); err != nil {
		s.review = true
		return o.fail(err)
	}
	if o.policyAuthority != nil {
		if err := o.policyAuthority.verify(ctx, s.candidate); err != nil {
			return o.fail(err)
		}
	}
	return nil
}

func (o *SourceRuntimeQEMU) Check(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return ErrState
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	return o.verify(ctx, s)
}

// Close releases only an unstarted join or its verified-settled finite fixture.
// It never closes either parent. Drift/uncertainty retains both reservations
// and original references; disposal of the VM is not product settlement.
func (o *SourceRuntimeQEMU) Close() error {
	ctx := context.Background()
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed {
		return nil
	}
	if o.accessAttempted && !o.accessSettled {
		return ErrBusy
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if err := o.verify(ctx, s); err != nil {
		return err
	}
	if err := o.lease.Close(); err != nil {
		if errors.Is(err, processowner.ErrBusy) {
			return ErrBusy
		}
		return o.fail(err)
	}
	s.runtime = nil
	o.closed = true
	return nil
}

func (SourceRuntimeQEMU) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*SourceRuntimeQEMU) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (SourceRuntimeQEMU) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-source-runtime{private}")
}

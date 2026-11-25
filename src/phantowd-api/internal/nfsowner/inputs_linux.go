//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// RetainedInputs binds one NFS candidate to the original policy, identities
// and mounted roster. It borrows policy and identity leases and owns the
// storage lease and export pins. No paths are granted to an execution backend.
type RetainedInputs struct {
	gate                     chan struct{}
	original                 *RetainedInputs
	policy                   *naspolicystore.Lease
	identity                 *identityowner.FileServiceLease
	storage                  *mountowner.MountedVolumeSet
	lease                    *mountowner.MountedVolumeSetLease
	roots                    *ExportRoots
	candidate                fileserviceplan.NFSv3Candidate
	activeRevision           uint64
	review, closed, attached bool
}

type inputsConstructionReview struct {
	constructionreview.Marker
	inputs *RetainedInputs
	cause  error
}

func (*inputsConstructionReview) Error() string        { return "NFS input construction retains review" }
func (e *inputsConstructionReview) Unwrap() error      { return e.cause }
func (*inputsConstructionReview) Is(target error) bool { return target == ErrReviewRequired }

// PrepareInputs prepares an enabled NFS candidate from original, admitted
// in-process authorities. The caller retains policy and identity through
// Close and keeps any original error from uncertain construction rollback.
func PrepareInputs(ctx context.Context, policy *naspolicystore.Lease, identity *identityowner.FileServiceLease, storage *mountowner.MountedVolumeSet, activeRevision uint64) (_ *RetainedInputs, _ fileserviceplan.NFSv3Candidate, result error) {
	if ctx == nil || policy == nil || identity == nil || storage == nil {
		return nil, fileserviceplan.NFSv3Candidate{}, ErrInvalid
	}
	lease, _, err := storage.Acquire(ctx)
	if err != nil {
		return nil, fileserviceplan.NFSv3Candidate{}, err
	}
	inputs := &RetainedInputs{
		gate: make(chan struct{}, 1), policy: policy, identity: identity, storage: storage, lease: lease, activeRevision: activeRevision,
	}
	inputs.original = inputs
	defer func() {
		if result == nil {
			return
		}
		cause, retain := constructionreview.Rollback(result, inputs.release)
		if retain {
			result = &inputsConstructionReview{inputs: inputs, cause: cause}
		} else {
			result = cause
		}
	}()
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, policy, activeRevision, identity, storage)
	if err != nil {
		return nil, fileserviceplan.NFSv3Candidate{}, err
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		return nil, fileserviceplan.NFSv3Candidate{}, err
	}
	inputs.candidate = candidate
	inputs.roots, err = NewExportRoots(ctx, candidate, lease)
	if err != nil {
		return nil, fileserviceplan.NFSv3Candidate{}, err
	}
	if err := errors.Join(policy.Verify(ctx), identity.Verify(ctx)); err != nil {
		return nil, fileserviceplan.NFSv3Candidate{}, err
	}
	return inputs, candidate, nil
}

// Check requires the prepared candidate and verifies the same original
// authorities. A failed live observation permanently requires review.
func (i *RetainedInputs) Check(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	return i.check(ctx, candidate, false)
}

func (i *RetainedInputs) check(ctx context.Context, candidate fileserviceplan.NFSv3Candidate, attached bool) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := i.enter(); err != nil {
		return err
	}
	defer i.leave()
	if i.review {
		return ErrReviewRequired
	}
	if i.closed || i.attached != attached {
		return ErrState
	}
	if !i.candidate.SameAs(candidate) {
		return ErrInvalid
	}
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, i.policy, i.activeRevision, i.identity, i.storage)
	if err != nil {
		i.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	current, err := plan.NFSv3TCPCandidate()
	if err != nil || !i.candidate.SameAs(current) {
		i.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	if err := i.roots.Check(ctx); err != nil {
		i.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	return nil
}

// Close releases storage before any transfer to a service Owner. After
// transfer, the Owner verifies stop and closes the inputs. The borrower
// retains policy and identity leases through closure.
func (i *RetainedInputs) Close() error {
	return i.close(false)
}

func (i *RetainedInputs) close(attached bool) error {
	if err := i.enter(); err != nil {
		return err
	}
	defer i.leave()
	if i.review {
		return ErrReviewRequired
	}
	if i.attached != attached {
		return ErrState
	}
	if err := i.release(); err != nil {
		i.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	return nil
}

func (i *RetainedInputs) enter() error {
	if i == nil || i.original != i {
		return ErrInvalid
	}
	select {
	case i.gate <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

func (i *RetainedInputs) leave() { <-i.gate }

func (i *RetainedInputs) release() error {
	if i.roots != nil {
		if err := i.roots.Close(); err != nil {
			return err
		}
		i.roots = nil
	}
	if i.lease != nil {
		if err := i.lease.Close(); err != nil {
			return err
		}
		i.lease = nil
	}
	i.closed = true
	return nil
}

func (RetainedInputs) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*RetainedInputs) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (RetainedInputs) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-retained-inputs{private}")
}

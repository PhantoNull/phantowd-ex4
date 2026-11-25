// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

// registeredNFS retains the claims for one NFS lifetime. The supervisor owns
// storage and closes it after all dependent service lifetimes end.
type registeredNFS struct {
	mu       sync.Mutex
	storage  *registeredStorage
	policy   *naspolicystore.Lease
	identity *identityowner.FileServiceLease
	inputs   *nfsowner.RetainedInputs
	owner    *nfsowner.Owner
	closed   bool
	review   error
}

type registeredNFSGrants struct {
	policy   *naspolicystore.Owner
	identity *identityowner.Owner
	storage  *registeredStorage
	desired  uint64
	active   uint64
	runtime  nfsowner.LinuxServiceGrants
}

// prepareRegisteredNFS is the Linux supervisor entry point for a confirmed
// policy revision. Empty exports remain dormant without holding a claim.
func prepareRegisteredNFS(ctx context.Context, grants registeredNFSGrants) (*registeredNFS, error) {
	return prepareRegisteredNFSWith(ctx, grants, nfsowner.NewManagedLinux)
}

// The QEMU legacy fixture supplies an alternative constructor in its
// build-tagged caller. Platform callers use prepareRegisteredNFS.
func prepareRegisteredNFSWith(ctx context.Context, grants registeredNFSGrants,
	construct func(context.Context, *nfsowner.RetainedInputs, nfsowner.LinuxServiceGrants) (*nfsowner.Owner, error)) (_ *registeredNFS, result error) {
	if ctx == nil || grants.policy == nil || grants.desired == 0 || construct == nil {
		return nil, nfsowner.ErrInvalid
	}
	policy, err := grants.policy.Acquire(ctx, grants.desired)
	if err != nil {
		return nil, err
	}
	s := &registeredNFS{storage: grants.storage, policy: policy}
	defer func() {
		cause, retained := constructionreview.Rollback(result, s.releaseUnstarted)
		if retained {
			result = s.retain(cause)
		}
	}()
	document, err := policy.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(document.FileServices.NFS.Exports) == 0 {
		if err := s.releaseClaims(); err != nil {
			return nil, s.retain(err)
		}
		return nil, nil
	}
	if grants.identity == nil || s.storage == nil {
		return nil, nfsowner.ErrInvalid
	}
	set, err := s.storage.Volumes(ctx)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, mountowner.ErrUnavailable
	}
	identity, err := grants.identity.FileServiceSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	s.identity, err = grants.identity.RetainFileServiceSnapshot(ctx, identity.Fingerprint)
	if err != nil {
		return nil, err
	}
	s.inputs, _, err = nfsowner.PrepareInputs(ctx, policy, s.identity, set, grants.active)
	if err != nil {
		return nil, err
	}
	grants.runtime.VerifyStorage = func(ctx context.Context) error {
		current, err := s.storage.Volumes(ctx)
		if err != nil {
			return err
		}
		if current != set {
			return mountowner.ErrReview
		}
		return nil
	}
	s.owner, err = construct(ctx, s.inputs, grants.runtime)
	if err != nil {
		if s.owner != nil {
			err = s.retain(err)
		}
		return nil, err
	}
	if s.owner == nil {
		return nil, nfsowner.ErrInvalid
	}
	return s, nil
}

func (s *registeredNFS) Start(ctx context.Context) error {
	if err := s.enter(ctx, false); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.observeOutcome(s.owner.Start(ctx))
}

func (s *registeredNFS) Check(ctx context.Context) error {
	if err := s.enter(ctx, false); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.observeOutcome(s.owner.Check(ctx))
}

// Close verifies service absence before releasing its independent claims.
// An uncertain outcome retains the original lifetime for review.
func (s *registeredNFS) Close(ctx context.Context) error {
	if err := s.enter(ctx, true); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.owner.Close(ctx); err != nil {
		return s.observeOutcome(err)
	}
	if err := s.releaseClaims(); err != nil {
		return s.retain(err)
	}
	s.closed = true
	return nil
}

func (s *registeredNFS) enter(ctx context.Context, allowClosed bool) error {
	if s == nil || ctx == nil {
		return nfsowner.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.mu.TryLock() {
		return nfsowner.ErrBusy
	}
	if s.review != nil {
		s.mu.Unlock()
		return s.review
	}
	if s.closed && !allowClosed {
		s.mu.Unlock()
		return nfsowner.ErrState
	}
	return nil
}

func (s *registeredNFS) observeOutcome(err error) error {
	if errors.Is(err, nfsowner.ErrReviewRequired) || constructionreview.Contains(err) {
		return s.retain(err)
	}
	return err
}

func (s *registeredNFS) releaseUnstarted() error {
	if s.inputs != nil {
		if err := s.inputs.Close(); err != nil {
			return err
		}
	}
	return s.releaseClaims()
}

func (s *registeredNFS) releaseClaims() error {
	if s.identity != nil {
		if err := s.identity.Release(); err != nil {
			return err
		}
		s.identity = nil
	}
	if err := s.policy.Release(); err != nil {
		return err
	}
	s.policy = nil
	return nil
}

func (s *registeredNFS) retain(cause error) error {
	s.review = &registeredNFSReview{lifetime: s, cause: cause}
	return s.review
}

type registeredNFSReview struct {
	constructionreview.Marker
	lifetime *registeredNFS
	cause    error
}

func (r *registeredNFSReview) Error() string {
	return fmt.Sprintf("registered NFS requires review: %s", r.cause)
}
func (r *registeredNFSReview) Unwrap() error { return r.cause }

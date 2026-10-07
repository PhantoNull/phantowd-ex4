//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
)

// NativeIdentityServiceQEMU is confined to disposable QEMU qualification. It
// supplies no HTTP interface, storage grants or product service authorization.
// Never copy a constructed coordinator; retain its original pointer.
type NativeIdentityServiceQEMU struct {
	owner                          *identityowner.Owner
	backend                        *NativeBackendQEMU
	lease                          *identityowner.FileServiceLease
	gate                           chan struct{}
	status                         atomic.Value
	checks                         uint64
	attempted, started, stopped    bool
	closed, review, closeUncertain bool
	runtimeClosed                  bool
}

type NativeIdentityStatusQEMU struct {
	State            string
	Checks           uint64
	IdentityRetained bool
	RuntimeClosed    bool
}

// The runtime is taken ONLY from the backend fixed by the identity Owner.
// Trusted fixture callers transfer lifecycle control; they must not operate
// aliases of the backend/runtime while this coordinator owns the service.
// A late uncertain construction returns the quarantined handle AND an error:
// retain the handle; never substitute a new lease or hide its retained authority.
func NewNativeIdentityServiceQEMU(ctx context.Context, owner *identityowner.Owner, expected [32]byte, backend *NativeBackendQEMU) (*NativeIdentityServiceQEMU, error) {
	if ctx == nil || owner == nil || backend == nil || expected == ([32]byte{}) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	backend.mu.RLock()
	valid := !backend.closed && backend.inner != nil && backend.runtime != nil
	backend.mu.RUnlock()
	if !valid {
		return nil, ErrInvalid
	}
	if err := backend.runtime.CheckNativeStartupQEMU(ctx); err != nil {
		return nil, err
	}
	lease, err := owner.RetainSMBFileServiceSnapshot(ctx, expected, backend)
	if err != nil {
		return nil, err
	}
	s := &NativeIdentityServiceQEMU{owner: owner, backend: backend, lease: lease, gate: make(chan struct{}, 1)}
	s.publish()
	if err := backend.runtime.CheckNativeStartupQEMU(ctx); err != nil {
		s.review, s.closeUncertain = true, true
		s.publish()
		return s, errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	return s, nil
}

func (s *NativeIdentityServiceQEMU) enter(ctx context.Context) error {
	if s == nil || ctx == nil || s.gate == nil || s.owner == nil || s.backend == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

// Start is single-use. Fresh complete identity verification happens outside the
// runtime gate on BOTH sides of daemon startup. This avoids recursive locking
// through the Owner-bound backend's observations. No runtime is caller-selected.
func (s *NativeIdentityServiceQEMU) Start(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || s.attempted {
		return runtimebundle.ErrReviewRequired
	}
	s.attempted = true
	if err := s.lease.Verify(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.backend.runtime.StartNativeDaemonQEMU(ctx); err != nil {
		// Runtime Start already performs its own bounded stop on failure.
		// Its error is not a settlement witness; do not retry that teardown.
		s.review, s.closeUncertain = true, true
		s.publish()
		return errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	s.started = true
	if err := s.lease.Verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.publish()
	return nil
}

func (s *NativeIdentityServiceQEMU) Observe(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	return s.observe(ctx)
}

// Disable is an explicit revision-checked transition through the SAME Owner's
// startup-fixed backend. Its verified successor replaces only this consumer;
// no caller supplies a token, fingerprint, runtime or executor. The exclusive
// supervision loop refuses concurrent mutation rather than racing that transfer.
func (s *NativeIdentityServiceQEMU) Disable(ctx context.Context, id string, expected uint64) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped {
		return runtimebundle.ErrReviewRequired
	}
	if id == "" || expected == 0 || expected > ^uint64(0)-2 {
		return ErrInvalid
	}
	previous := s.lease
	successor, err := s.owner.SMB(id).DisableForFileService(ctx, expected, previous)
	// Even a surprising non-nil successor with an error must stay owned. Never
	// drop the authority returned by the atomic transition to simplify cleanup.
	if successor != nil {
		s.lease = successor
	}
	if err != nil {
		if successor == nil && errors.Is(err, smbprovision.ErrConflict) && !errors.Is(err, identityowner.ErrReview) {
			return err // Qualified pre-intent revision refusal, not a retry.
		}
		return s.quarantine(err)
	}
	if successor == nil || !errors.Is(previous.Verify(ctx), identityowner.ErrReview) {
		return s.quarantine(identityowner.ErrReview)
	}
	if err := successor.Verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.publish()
	return nil
}

func (s *NativeIdentityServiceQEMU) observe(ctx context.Context) error {
	if s.closed || s.review || !s.started || s.stopped {
		return runtimebundle.ErrReviewRequired
	}
	// Complete passdb observation runs retained workers that revalidate the
	// SAME code/config/state/live daemon before and after execution. The lease
	// also rechecks registry/native/Samba journals and the complete Unix census.
	if err := s.lease.Verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.checks++
	s.publish()
	return nil
}

// One exclusive lifecycle loop, with a fixed idle interval and no catch-up
// scans. Telemetry remains readable; competing mutations/observations refuse.
// Accepted cancellation stops the complete daemon/client set, retains identity
// and does not close inputs or restart. Close is a separate explicit operation.
func (s *NativeIdentityServiceQEMU) Supervise(ctx context.Context, interval time.Duration) error {
	if interval < time.Second || interval > time.Hour {
		return ErrInvalid
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped {
		return runtimebundle.ErrReviewRequired
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.stop(); err != nil {
				return errors.Join(ctx.Err(), err)
			}
			return ctx.Err()
		case <-timer.C:
			if ctx.Err() != nil {
				continue
			}
			if err := s.observe(ctx); err != nil {
				return err
			}
			timer.Reset(interval)
		}
	}
}

func (s *NativeIdentityServiceQEMU) stop() error {
	if s.closeUncertain {
		return runtimebundle.ErrReviewRequired
	}
	if !s.stopped {
		if err := s.backend.runtime.StopNativeServiceQEMU(context.Background()); err != nil {
			s.review, s.closeUncertain = true, true
			s.publish()
			return errors.Join(runtimebundle.ErrReviewRequired, err)
		}
		s.stopped = true
	}
	s.publish()
	return nil
}

func (s *NativeIdentityServiceQEMU) quarantine(cause error) error {
	s.review = true
	err := s.stop()
	s.publish()
	return errors.Join(runtimebundle.ErrReviewRequired, cause, err)
}

// Full runtime closure precedes identity Release, both outside the Owner gate.
// The identity Owner itself stays owned by the trusted caller. On any uncertain
// runtime close, keep the lease and refuse subsequent close attempts; a later
// nil return from the raw runtime would not settle that original uncertainty.
func (s *NativeIdentityServiceQEMU) Close(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closeUncertain {
		return runtimebundle.ErrReviewRequired
	}
	if !s.closed {
		if err := s.backend.runtime.Close(context.Background()); err != nil {
			s.review, s.closeUncertain = true, true
			s.publish()
			return errors.Join(runtimebundle.ErrReviewRequired, err)
		}
		s.runtimeClosed, s.stopped = true, true
		if err := s.lease.Release(); err != nil {
			s.review, s.closeUncertain = true, true
			s.publish()
			return errors.Join(runtimebundle.ErrReviewRequired, err)
		}
		s.lease = nil
		s.closed = true
		s.publish()
	}
	if s.review {
		return runtimebundle.ErrReviewRequired
	}
	return nil
}

// Status is immutable redacted telemetry, not a lease or an admission witness.
// It uses no authority/runtime gate and is readable during supervision.
func (s *NativeIdentityServiceQEMU) Status() (NativeIdentityStatusQEMU, error) {
	if s == nil {
		return NativeIdentityStatusQEMU{}, ErrInvalid
	}
	value := s.status.Load()
	if value == nil {
		return NativeIdentityStatusQEMU{}, ErrInvalid
	}
	return value.(NativeIdentityStatusQEMU), nil
}

func (s *NativeIdentityServiceQEMU) publish() {
	state := "prepared"
	if s.started {
		state = "ready"
	}
	if s.stopped || s.closed {
		state = "stopped"
	}
	if s.review {
		state = "review-required"
	}
	s.status.Store(NativeIdentityStatusQEMU{State: state, Checks: s.checks, IdentityRetained: s.lease != nil, RuntimeClosed: s.runtimeClosed})
}

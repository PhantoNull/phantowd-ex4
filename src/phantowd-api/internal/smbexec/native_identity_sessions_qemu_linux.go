//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// Fixed disposable qualification helpers, not product commands. The caller
// chooses no program, credentials, input stream, backend or session usernames.
// Keep even fixture client lifecycle under the SAME coordinator serialization.
func (s *NativeIdentityServiceQEMU) StartNativeSessionPairQEMU(ctx context.Context) (NativeSessionPairQEMU, error) {
	if err := s.enter(ctx); err != nil {
		return NativeSessionPairQEMU{}, err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped {
		return NativeSessionPairQEMU{}, runtimebundle.ErrReviewRequired
	}
	if err := s.lease.Verify(ctx); err != nil {
		return NativeSessionPairQEMU{}, s.quarantine(err)
	}
	if err := s.backend.runtime.StartNativeClientsQEMU(ctx); err != nil {
		// The runtime already attempted bounded teardown. Its error is NOT a
		// settlement witness; retain uncertainty without another stop attempt.
		s.review, s.closeUncertain = true, true
		s.publish()
		return NativeSessionPairQEMU{}, errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	pair, err := s.backend.ObserveNativeSessionPairQEMU(ctx)
	if err != nil {
		return NativeSessionPairQEMU{}, s.quarantine(err)
	}
	if err := s.lease.Verify(ctx); err != nil {
		return NativeSessionPairQEMU{}, s.quarantine(err)
	}
	return pair, nil
}

// The private witness identifies the exact original peer session and backend,
// not merely a new successful login or another connection from the same IP.
// Require BOTH that continuity and fresh target-denial/peer-authentication.
func (s *NativeIdentityServiceQEMU) VerifyNativeDisabledPairQEMU(ctx context.Context, pair NativeSessionPairQEMU) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped {
		return runtimebundle.ErrReviewRequired
	}
	if pair.backend != s.backend || pair.target.SessionID == "" || pair.peer.SessionID == "" {
		return ErrInvalid
	}
	if err := s.lease.Verify(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.backend.VerifyNativePeerSessionQEMU(ctx, pair); err != nil {
		return s.quarantine(err)
	}
	if err := s.backend.runtime.VerifyNativeIdleDisableQEMU(ctx); err != nil {
		return s.quarantine(err)
	}
	return nil
}

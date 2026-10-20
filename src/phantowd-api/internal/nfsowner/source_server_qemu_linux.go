//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// Fixed original-source adapter. Each callback owns the join/root gates for
// one operation only. No runtime gate crosses storage/identity callbacks;
// no operation replaces original authority or runtime inputs.
type sourceServerBackendQEMU struct {
	source *SourceRuntimeQEMU
	roots  *exportRoots
}

// NewServerOwnerFixtureQEMU prepares one original-source lifetime, starting no
// service. Existing ARM/source guards apply; no backend/path argument or
// descriptor escapes. This is not a product service constructor.
func (o *SourceRuntimeQEMU) NewServerOwnerFixtureQEMU(ctx context.Context) (*Owner, error) {
	if err := o.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-o.gate }()
	if o.review {
		return nil, ErrReviewRequired
	}
	if o.closed || o.serverOwner != nil || o.accessAttempted {
		return nil, ErrState
	}
	if o.policyAuthority == nil {
		return nil, ErrInvalid
	}
	s, err := o.roots.enter()
	if err != nil {
		return nil, err
	}
	defer s.leave()
	if err := o.prepareAccessLocked(ctx, s, false, false); err != nil {
		return nil, err
	}
	return newSourceServerOwnerQEMU(o, s)
}

func newSourceServerOwnerQEMU(o *SourceRuntimeQEMU, roots *exportRoots) (*Owner, error) {
	if o == nil || o.original != o || roots == nil || roots.runtime != o ||
		o.policyAuthority == nil || o.access == nil || o.serverOwner != nil {
		return nil, ErrInvalid
	}
	owner, err := NewQEMU(roots.candidate, &sourceServerBackendQEMU{source: o, roots: roots})
	if err != nil {
		return nil, err
	}
	o.serverOwner = owner
	return owner, nil
}

// Stop/stopped verification may observe a reviewed JOIN. The original runtime
// guards still apply: uncertain/partial-start cleanup is not fictional success.
func (b *sourceServerBackendQEMU) operate(ctx context.Context, allowReview bool, call func(*SourceRuntimeQEMU, *exportRoots) error) error {
	if b == nil || b.source == nil || b.roots == nil || call == nil {
		return ErrInvalid
	}
	o := b.source
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if s != b.roots || s.runtime != o || o.closed || s.closed || s.closeUncertain ||
		o.serverOwner == nil || o.serverOwner.inner == nil || o.serverOwner.inner.backend != b {
		return o.fail(ErrReviewRequired)
	}
	if o.review && !allowReview {
		return ErrReviewRequired
	}
	err = call(o, s)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return o.fail(err)
	}
	return nil
}

func (b *sourceServerBackendQEMU) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	return b.operate(ctx, false, func(o *SourceRuntimeQEMU, s *exportRoots) error {
		if !candidate.EquivalentTo(s.candidate) {
			return ErrInvalid
		}
		return o.verify(ctx, s)
	})
}

func (b *sourceServerBackendQEMU) VerifyStopped(ctx context.Context) error {
	return b.operate(ctx, true, func(o *SourceRuntimeQEMU, _ *exportRoots) error {
		return o.access.CheckServerStoppedFixtureQEMU(ctx)
	})
}

func (b *sourceServerBackendQEMU) Start(ctx context.Context) error {
	return b.operate(ctx, false, func(o *SourceRuntimeQEMU, _ *exportRoots) error {
		if err := o.access.StartServerFixtureQEMU(ctx); err != nil {
			return err
		}
		o.accessServer = true
		return nil
	})
}

func (b *sourceServerBackendQEMU) VerifyReady(ctx context.Context) error {
	return b.operate(ctx, false, func(o *SourceRuntimeQEMU, _ *exportRoots) error {
		if !o.accessServer {
			return ErrState
		}
		return o.access.CheckServerFixtureQEMU(ctx)
	})
}

// The original Owner supplies the independent cleanup context. Do not require
// a healthy policy observation here: policy refusal must not suppress an
// already-admitted stop. The lower runtime still enforces its original guards;
// its uncertain/partial-start failures retain review, not fictional cleanup.
func (b *sourceServerBackendQEMU) Stop(ctx context.Context) error {
	return b.operate(ctx, true, func(o *SourceRuntimeQEMU, _ *exportRoots) error {
		if err := o.access.StopServerFixtureQEMU(ctx); err != nil {
			// A reviewed Stop never becomes normal success. Only a separate
			// fresh original-reference witness may record actual absence.
			if o.access.CheckServerStoppedFixtureQEMU(ctx) == nil {
				o.accessServer = false
			}
			return err
		}
		o.accessServer = false
		return nil
	})
}

func (b *sourceServerBackendQEMU) Release(ctx context.Context) error {
	return b.operate(ctx, false, func(o *SourceRuntimeQEMU, _ *exportRoots) error {
		if o.accessServer || o.accessSettled || o.accessVolume == nil {
			return ErrReviewRequired
		}
		if err := o.access.Close(ctx); err != nil {
			return err
		}
		if err := o.accessVolume.Close(); err != nil {
			return err
		} // Original uncertain-close object retained, no retry.
		o.accessVolume = nil
		o.accessSettled = true
		return nil
	})
}

// Same original Owner gate and fixed synthetic-data operation. No path,
// payload or replacement backend is accepted. Lower gates return before
// independently budgeted Owner compensation on an admitted failure.
func (o *Owner) ExerciseSourceIOFixtureQEMU(ctx context.Context) error {
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state != Running {
		return ErrState
	}
	b, ok := s.backend.(*sourceServerBackendQEMU)
	if !ok {
		return ErrInvalid
	}
	if err := s.check(ctx); err != nil {
		return err
	}
	err = b.operate(ctx, false, func(source *SourceRuntimeQEMU, _ *exportRoots) error {
		return source.access.ExerciseServerIOFixtureQEMU(ctx)
	})
	if err != nil {
		return s.review(err, true)
	}
	return s.check(ctx)
}

// Read-only witness AFTER original Owner review. No Stop retry, claim refresh,
// reference release or clearing of review is performed by this diagnostic.
func (o *SourceRuntimeQEMU) VerifyServerStoppedRetainedFixtureQEMU(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if !o.review || o.cause == nil || o.serverOwner == nil || o.access == nil ||
		o.accessServer || o.accessSettled || o.accessVolume == nil {
		return ErrState
	}
	state, err := o.serverOwner.Observe()
	if err != nil {
		return err
	}
	if state != ReviewRequired {
		return ErrState
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if s.runtime != o || s.closed || s.closeUncertain || s.verify(ctx) != nil {
		return ErrReviewRequired
	}
	// The lower stopped reader rechecks the ORIGINAL lease/code/source/control
	// references, including the distinct reviewed-retention path. A healthy
	// admission check here would incorrectly reject that verified review state.
	return o.access.CheckServerStoppedFixtureQEMU(ctx)
}

// Positive real-server supervision evidence is IDLE cancellation, not periodic
// scan timing. Check is exercised explicitly before this fixed loop. The hour
// interval avoids a timing-based race between a running sample and cancellation;
// the original Owner gate proves admission/exclusion before we cancel it.
func stopSourceServerThroughSupervisionQEMU(ctx context.Context, owner *Owner) error {
	loop, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(loop, time.Hour) }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := owner.Observe()
		if errors.Is(err, ErrBusy) {
			break
		}
		select {
		case result := <-done:
			return errors.Join(ErrInvalid, result)
		case <-ctx.Done():
			cancel()
			return errors.Join(ctx.Err(), <-done)
		case <-ticker.C:
		}
	}
	for _, operation := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if !errors.Is(operation(ctx), ErrBusy) {
			cancel()
			return errors.Join(ErrInvalid, <-done)
		}
	}
	cancel()
	result := <-done
	if !errors.Is(result, context.Canceled) || errors.Is(result, ErrReviewRequired) {
		return errors.Join(ErrInvalid, result)
	}
	state, err := owner.Observe()
	if err != nil || state != Stopped || !errors.Is(owner.Start(ctx), ErrState) {
		return errors.Join(ErrInvalid, err)
	}
	return ctx.Err()
}

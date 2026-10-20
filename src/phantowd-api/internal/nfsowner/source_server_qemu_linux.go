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

// Fixed adapter used ONLY while the containing finite source campaign owns
// both join/root gates. It never calls their public gate-taking methods, swaps
// inputs, or releases borrowed policy/identity/storage authorities. Runtime
// operations return before callbacks enter another authority domain.
type sourceServerBackendQEMU struct {
	source *SourceRuntimeQEMU
	roots  *exportRoots
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

func (b *sourceServerBackendQEMU) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	if !candidate.EquivalentTo(b.roots.candidate) {
		return b.source.fail(ErrInvalid)
	}
	return b.source.verify(ctx, b.roots)
}

func (b *sourceServerBackendQEMU) VerifyStopped(ctx context.Context) error {
	if err := b.source.access.CheckServerStoppedFixtureQEMU(ctx); err != nil {
		return b.source.fail(err)
	}
	return nil
}

func (b *sourceServerBackendQEMU) Start(ctx context.Context) error {
	if err := b.source.access.StartServerFixtureQEMU(ctx); err != nil {
		return b.source.fail(err)
	}
	b.source.accessServer = true
	return nil
}

func (b *sourceServerBackendQEMU) VerifyReady(ctx context.Context) error {
	if !b.source.accessServer {
		return b.source.fail(ErrState)
	}
	if err := b.source.access.CheckServerFixtureQEMU(ctx); err != nil {
		return b.source.fail(err)
	}
	return nil
}

// The original Owner supplies the independent cleanup context. Do not require
// a healthy policy observation here: policy refusal must not suppress an
// already-admitted stop. The lower runtime still enforces its original guards;
// its uncertain/partial-start failures retain review, not fictional cleanup.
func (b *sourceServerBackendQEMU) Stop(ctx context.Context) error {
	if err := b.source.access.StopServerFixtureQEMU(ctx); err != nil {
		return b.source.fail(err)
	}
	b.source.accessServer = false
	return nil
}

func (b *sourceServerBackendQEMU) Release(ctx context.Context) error {
	o := b.source
	if o.accessServer || o.review || o.accessSettled || o.accessVolume == nil {
		return o.fail(ErrReviewRequired)
	}
	if err := o.access.Close(ctx); err != nil {
		return o.fail(err)
	}
	if err := o.accessVolume.Close(); err != nil {
		return o.fail(err) // Keep the original uncertain-close object; no retry.
	}
	o.accessVolume = nil
	o.accessSettled = true
	return ctx.Err()
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

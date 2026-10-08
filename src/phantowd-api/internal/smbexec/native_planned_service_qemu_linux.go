//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// NativePlannedInputsQEMU fixes trusted fixture authorities at construction.
// The containing service takes lifecycle control only on a non-nil return.
// Neither this tuple nor a prepared service is product activation authority.
type NativePlannedInputsQEMU struct {
	Policy         fileservice.Config
	ActiveRevision uint64
	Identity       *identityowner.Owner
	Storage        *mountowner.MountedVolumeSet
	Shares         *mountowner.ServiceSharePinsQEMU
	Backend        *NativeBackendQEMU
}

// This fixed disposable composition owns identity, original share pins and
// the backend's startup-fixed runtime together. A prepared tuple never enables
// a legacy start API. Its policy is a private copy, not a product policy lease.
// Trusted callers must not operate lifecycle aliases after a non-nil return.
type NativePlannedServiceQEMU struct {
	inputs        NativePlannedInputsQEMU
	plan          fileserviceplan.Plan
	roles         fileserviceplan.SambaRoleCandidate
	lease         *identityowner.FileServiceLease
	gate          chan struct{}
	status        atomic.Value
	checks        uint64
	attempted     bool
	started       bool
	dataAttempted bool
	dataVerified  bool
	stopped       bool
	closed        bool
	review        bool
	runtimeClosed bool
	closeErr      error
	pendingRoots  []mountowner.ServiceShareDescriptorQEMU
}

type NativePlannedStatusQEMU struct {
	State            string
	Checks           uint64
	IdentityRetained bool
	SharesRetained   bool
	RuntimeClosed    bool
	DataVerified     bool
}

func NewNativePlannedServiceQEMU(ctx context.Context, inputs NativePlannedInputsQEMU) (*NativePlannedServiceQEMU, error) {
	if ctx == nil || inputs.Identity == nil || inputs.Storage == nil || inputs.Shares == nil || inputs.Backend == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inputs.Backend.mu.RLock()
	valid := !inputs.Backend.closed && inputs.Backend.inner != nil && inputs.Backend.runtime != nil
	inputs.Backend.mu.RUnlock()
	if !valid || inputs.Policy.Validate() != nil || len(inputs.Policy.NFS.Exports) != 0 {
		return nil, ErrInvalid
	}
	// Reuse the bounded combined-policy decoder, rather than retaining caller
	// slice aliases or adding a second ad-hoc policy grammar.
	encoded, err := json.Marshal(inputs.Policy)
	if err != nil {
		return nil, ErrInvalid
	}
	inputs.Policy, err = fileservice.DecodeConfig(bytes.NewReader(encoded))
	clear(encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := inputs.Shares.VerifySourceSetQEMU(inputs.Storage); err != nil {
		return nil, err // The caller still owns the original pin on early refusal.
	}
	plan, err := fileserviceplan.BuildFromOwners(ctx, inputs.Policy, inputs.ActiveRevision, inputs.Identity, inputs.Storage)
	if err != nil {
		return nil, err
	}
	roles, err := plan.SambaRoleCandidate()
	if err != nil {
		return nil, err
	}
	candidate, err := roles.ServiceCandidate()
	if err != nil || candidate.VerifySharePinsQEMU(inputs.Shares) != nil {
		return nil, ErrInvalid
	}
	lease, err := inputs.Identity.RetainSMBFileServiceSnapshot(ctx, plan.Freshness().IdentityFingerprint, inputs.Backend)
	if err != nil {
		return nil, err
	}
	s := &NativePlannedServiceQEMU{inputs: inputs, plan: plan, roles: roles, lease: lease, gate: make(chan struct{}, 1)}
	s.publish()
	// From this point a failure returns the service AND error. No defer releases
	// authority, loses a quarantined handle or retries uncertain cleanup.
	if err := s.verify(ctx); err != nil {
		return s, s.quarantine(err)
	}
	roots, err := inputs.Shares.DuplicateRoots()
	if err != nil {
		return s, s.quarantine(err)
	}
	prepareErr := inputs.Backend.runtime.PreparePlannedDataInputsQEMU(ctx, roles, roots)
	for _, root := range roots {
		if err := root.File.Close(); err != nil {
			// The runtime and original pin remain owned. The uncertain duplicate
			// itself must remain referenced, and no later duplicate is released.
			s.pendingRoots = roots
			s.closeErr = err
			return s, s.quarantine(errors.Join(prepareErr, err))
		}
	}
	if prepareErr != nil {
		return s, s.quarantine(prepareErr)
	}
	if err := s.verify(ctx); err != nil {
		return s, s.quarantine(err)
	}
	s.publish()
	return s, nil
}

func (s *NativePlannedServiceQEMU) enter(ctx context.Context) error {
	if s == nil || ctx == nil || s.gate == nil {
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

// All storage/identity observations occur OUTSIDE the runtime gate. The ordered
// storage -> identity compiler may enter the fixed backend's retained workers;
// reversing that order or invoking it from a runtime callback would deadlock.
func (s *NativePlannedServiceQEMU) verify(ctx context.Context) error {
	if err := s.inputs.Shares.VerifySourceSetQEMU(s.inputs.Storage); err != nil {
		return err
	}
	candidate, err := s.roles.ServiceCandidate()
	if err != nil || candidate.VerifySharePinsQEMU(s.inputs.Shares) != nil {
		return runtimebundle.ErrReviewRequired
	}
	fresh, err := fileserviceplan.BuildFromRetainedOwners(ctx, s.inputs.Policy, s.inputs.ActiveRevision, s.lease, s.inputs.Storage)
	if err != nil || !s.plan.FreshAgainst(fresh.Freshness()) {
		return errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	return nil
}

func (s *NativePlannedServiceQEMU) Observe(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	return s.observe(ctx)
}

func (s *NativePlannedServiceQEMU) observe(ctx context.Context) error {
	if s.closed || s.review || s.stopped {
		return runtimebundle.ErrReviewRequired
	}
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.checks++
	s.publish()
	return nil
}

// One exclusive lifecycle loop; no catch-up scans or replacement authorities.
// Complete storage-first/identity observations stay outside the runtime gate.
// Accepted idle cancellation stops the whole owned group before returning,
// retaining BOTH originals until a separate successful full runtime Close.
// Any failed scan/stop remains review without restart or uncertainty retry.
func (s *NativePlannedServiceQEMU) Supervise(ctx context.Context, interval time.Duration) error {
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
			return errors.Join(ctx.Err(), s.stop())
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

// Start is a separate planned-service admission; legacy runtime start remains
// blocked by the inert service role. No caller supplies a runtime or backend.
func (s *NativePlannedServiceQEMU) Start(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || s.attempted {
		return runtimebundle.ErrReviewRequired
	}
	s.attempted = true
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.inputs.Backend.runtime.StartPlannedDaemonQEMU(ctx); err != nil {
		// Runtime startup owns its bounded failure stop. Its error is not a
		// settlement witness: keep both original authorities and never retry.
		s.closeErr, s.review = err, true
		s.publish()
		return errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	s.started = true
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.publish()
	return nil
}

// VerifyDataAccess is a fixed disposable qualification through this service's
// startup-bound runtime. It accepts no replacement authority or command.
func (s *NativePlannedServiceQEMU) VerifyDataAccess(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped || s.dataAttempted {
		return runtimebundle.ErrReviewRequired
	}
	s.dataAttempted = true
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.inputs.Backend.runtime.ProbePlannedDataAccessQEMU(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	s.dataVerified = true
	s.publish()
	return nil
}

func (s *NativePlannedServiceQEMU) stop() error {
	if s.closeErr != nil {
		s.publish() // Preserve review telemetry even when uncertain cleanup cannot retry.
		return errors.Join(runtimebundle.ErrReviewRequired, s.closeErr)
	}
	if s.started && !s.stopped {
		if err := s.inputs.Backend.runtime.StopNativeServiceQEMU(context.Background()); err != nil {
			s.closeErr, s.review = err, true
		} else {
			s.stopped = true
		}
	}
	s.publish()
	if s.closeErr != nil {
		return errors.Join(runtimebundle.ErrReviewRequired, s.closeErr)
	}
	return nil
}

func (s *NativePlannedServiceQEMU) quarantine(cause error) error {
	s.review = true
	stopErr := s.stop()
	return errors.Join(runtimebundle.ErrReviewRequired, cause, stopErr)
}

// Runtime copies close before EITHER original authority is released. A first
// uncertain release remains observable and is never retried. The trusted caller
// separately owns the identity Owner, mounted roster and handoff mount lifecycle.
func (s *NativePlannedServiceQEMU) Close(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closeErr != nil {
		return errors.Join(runtimebundle.ErrReviewRequired, s.closeErr)
	}
	if !s.closed {
		if err := s.inputs.Backend.runtime.Close(context.Background()); err != nil {
			s.closeErr = err
			return s.quarantine(err)
		}
		s.runtimeClosed, s.stopped = true, true
		if err := s.lease.Release(); err != nil {
			s.closeErr = err
			return s.quarantine(err)
		}
		s.lease = nil
		if err := s.inputs.Shares.Close(); err != nil {
			s.closeErr = err
			return s.quarantine(err)
		}
		s.inputs.Shares = nil
		s.closed = true
		s.publish()
	}
	if s.review {
		return runtimebundle.ErrReviewRequired
	}
	return nil
}

func (s *NativePlannedServiceQEMU) Status() (NativePlannedStatusQEMU, error) {
	if s == nil {
		return NativePlannedStatusQEMU{}, ErrInvalid
	}
	value := s.status.Load()
	if value == nil {
		return NativePlannedStatusQEMU{}, ErrInvalid
	}
	return value.(NativePlannedStatusQEMU), nil
}

func (s *NativePlannedServiceQEMU) publish() {
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
	s.status.Store(NativePlannedStatusQEMU{State: state, Checks: s.checks, IdentityRetained: s.lease != nil,
		SharesRetained: s.inputs.Shares != nil, RuntimeClosed: s.runtimeClosed, DataVerified: s.dataVerified})
}

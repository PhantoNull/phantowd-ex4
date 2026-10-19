//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package nfsowner contains the experimental, QEMU-only NFS lifetime owner.
// It has no product constructor, HTTP interface or generic process launcher.
package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

var (
	ErrInvalid        = errors.New("invalid NFS owner")
	ErrState          = errors.New("NFS owner transition refused")
	ErrReviewRequired = errors.New("NFS owner requires review")
	ErrBusy           = errors.New("NFS owner busy")
	ErrPrivate        = errors.New("NFS owner is private")
)

type State string

const (
	Prepared       State = "prepared"
	Disabled       State = "disabled"
	Running        State = "running"
	Stopped        State = "stopped"
	Closed         State = "closed"
	ReviewRequired State = "review-required"
)

// QEMUBackend is trusted fixture code, fixed at construction. It retains the
// original domain and input references. No operation accepts replacement inputs.
type QEMUBackend interface {
	CheckInputs(context.Context, fileserviceplan.NFSv3Candidate) error
	VerifyStopped(context.Context) error
	Start(context.Context) error
	VerifyReady(context.Context) error
	Stop(context.Context) error
	Release(context.Context) error
}

// Owner is an opaque, non-copyable lifetime. It retains its backend even when
// settlement/closure is uncertain; no reviewed instance can be reopened.
type Owner struct{ inner *lifetime }

type lifetime struct {
	original  *Owner
	gate      chan struct{}
	backend   QEMUBackend
	candidate fileserviceplan.NFSv3Candidate
	state     State
	enabled   bool
}

// NewQEMU captures trusted synthetic inputs only. It performs no I/O and does
// not prove the backend's domain/input authority. The caller retains ownership
// on error; successful construction transfers the lifetime to the returned Owner.
func NewQEMU(candidate fileserviceplan.NFSv3Candidate, backend QEMUBackend) (*Owner, error) {
	enabled, _, _, err := candidate.Documents()
	if err != nil || backend == nil {
		return nil, ErrInvalid
	}
	switch value := reflect.ValueOf(backend); value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrInvalid
		}
	}
	o := &Owner{}
	o.inner = &lifetime{original: o, gate: make(chan struct{}, 1), backend: backend, candidate: candidate, state: Prepared, enabled: enabled}
	return o, nil
}

func (o *Owner) Start(ctx context.Context) error {
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state != Prepared {
		return ErrState
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := checked(ctx, func() error { return s.backend.CheckInputs(ctx, s.candidate) }); err != nil {
		return s.review(err, false)
	}
	if err := checked(ctx, func() error { return s.backend.VerifyStopped(ctx) }); err != nil {
		return s.review(err, false)
	}
	if !s.enabled {
		s.state = Disabled
		return nil
	}
	if err := checked(ctx, func() error { return s.backend.Start(ctx) }); err != nil {
		return s.review(err, true)
	}
	if err := checked(ctx, func() error { return s.backend.VerifyReady(ctx) }); err != nil {
		return s.review(err, true)
	}
	if err := checked(ctx, func() error { return s.backend.CheckInputs(ctx, s.candidate) }); err != nil {
		return s.review(err, true)
	}
	s.state = Running
	return nil
}
func (o *Owner) Stop(ctx context.Context) error {
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	return s.stop(ctx)
}

// Check serializes one fresh check, not an automatic polling/restart loop.
func (o *Owner) Check(ctx context.Context) error {
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	return s.check(ctx)
}

func (s *lifetime) check(ctx context.Context) error {
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state != Running && s.state != Disabled {
		return ErrState
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	running := s.state == Running
	if err := checked(ctx, func() error { return s.backend.CheckInputs(ctx, s.candidate) }); err != nil {
		return s.review(err, running)
	}
	probe := s.backend.VerifyStopped
	if running {
		probe = s.backend.VerifyReady
	}
	if err := checked(ctx, func() error { return probe(ctx) }); err != nil {
		return s.review(err, running)
	}
	if err := checked(ctx, func() error { return s.backend.CheckInputs(ctx, s.candidate) }); err != nil {
		return s.review(err, running)
	}
	return nil
}
func (s *lifetime) stop(caller context.Context) error {
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state == Stopped {
		return nil
	}
	if s.state != Running {
		return ErrState
	}
	// Once accepted, settlement gets its own bounded context. Caller cancellation
	// must not suppress stop; a late canceled result still cannot release inputs.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := checked(ctx, func() error { return s.backend.Stop(ctx) }); err != nil {
		return s.review(err, false)
	}
	if err := checked(ctx, func() error { return s.backend.VerifyStopped(ctx) }); err != nil {
		return s.review(err, false)
	}
	if err := caller.Err(); err != nil {
		return s.review(err, false)
	}
	s.state = Stopped
	return nil
}
func (o *Owner) Close(ctx context.Context) error {
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state == Closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.state == Running {
		if err := s.stop(ctx); err != nil {
			return err
		}
	}
	if err := checked(ctx, func() error { return s.backend.CheckInputs(ctx, s.candidate) }); err != nil {
		return s.review(err, false)
	}
	if err := checked(ctx, func() error { return s.backend.VerifyStopped(ctx) }); err != nil {
		return s.review(err, false)
	}
	if err := checked(ctx, func() error { return s.backend.Release(ctx) }); err != nil {
		return s.review(err, false)
	}
	s.state = Closed
	return nil
}
func (s *lifetime) review(cause error, compensate bool) error {
	s.state = ReviewRequired
	if compensate {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if checked(ctx, func() error { return s.backend.Stop(ctx) }) == nil {
			_ = checked(ctx, func() error { return s.backend.VerifyStopped(ctx) })
		}
	}
	// Only standard cancellation causes survive. Backend errors may contain
	// private paths/identities; neither their text nor their chain is published.
	if errors.Is(cause, context.Canceled) {
		return errors.Join(ErrReviewRequired, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return errors.Join(ErrReviewRequired, context.DeadlineExceeded)
	}
	return ErrReviewRequired
}
func checked(ctx context.Context, call func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := call()
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	return err
}

// Observe is historical lifecycle state, NOT a fresh kernel health observation.
func (o *Owner) Observe() (State, error) {
	s, err := o.acquire(context.Background())
	if err != nil {
		return "", err
	}
	defer s.unlock()
	return s.state, nil
}
func (o *Owner) acquire(ctx context.Context) (*lifetime, error) {
	if o == nil || o.inner == nil || o.inner.original != o || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := o.inner
	select {
	case s.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			s.unlock()
			return nil, err
		}
		return s, nil
	default:
		return nil, ErrBusy
	}
}
func (s *lifetime) unlock()                { <-s.gate }
func (Owner) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Owner) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (Owner) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "nfs-owner{private}") }

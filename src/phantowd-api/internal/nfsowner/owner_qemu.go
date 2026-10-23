//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package nfsowner implements an experimental memory-only service lifetime.
// It has no kernel backend or product constructor.
package nfsowner

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

var ErrInvalid = errors.New("invalid NFS owner")
var ErrReviewRequired = errors.New("NFS owner requires review")
var ErrBusy = errors.New("NFS owner busy")
var ErrState = errors.New("NFS owner transition refused")

type State string

const (
	Prepared       State = "prepared"
	Disabled       State = "disabled"
	Running        State = "running"
	Stopped        State = "stopped"
	Closed         State = "closed"
	ReviewRequired State = "review-required"
)

// QEMUBackend is fixed trusted fixture code, not a kernel authority grant.
type QEMUBackend interface {
	CheckInputs(context.Context, fileserviceplan.NFSv3Candidate) error
	VerifyStopped(context.Context) error
	Start(context.Context) error
	VerifyReady(context.Context) error
	Stop(context.Context) error
	Release(context.Context) error
}

type Owner struct {
	original  *Owner
	gate      chan struct{}
	backend   QEMUBackend
	candidate fileserviceplan.NFSv3Candidate
	state     State
	enabled   bool
}

// NewQEMU performs no I/O. The caller retains ownership on construction error.
func NewQEMU(candidate fileserviceplan.NFSv3Candidate, backend QEMUBackend) (*Owner, error) {
	enabled, _, _, err := candidate.Documents()
	if err != nil || backend == nil {
		return nil, ErrInvalid
	}
	switch v := reflect.ValueOf(backend); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil, ErrInvalid
		}
	}
	o := &Owner{backend: backend, candidate: candidate, state: Prepared, enabled: enabled, gate: make(chan struct{}, 1)}
	o.original = o
	return o, nil
}

func (o *Owner) Close(ctx context.Context) error {
	if err := o.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.state == ReviewRequired {
		return ErrReviewRequired
	}
	if o.state == Closed {
		return nil
	}
	if o.state == Running {
		if err := o.stop(ctx); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, call := range []func() error{
		func() error { return o.backend.CheckInputs(ctx, o.candidate) },
		func() error { return o.backend.VerifyStopped(ctx) },
		func() error { return o.backend.Release(ctx) },
	} {
		err := ctx.Err()
		if err == nil {
			err = call()
		}
		if cause := ctx.Err(); cause != nil {
			err = cause
		}
		if err != nil {
			return o.review(err)
		}
	}
	o.state = Closed
	return nil
}

func (o *Owner) review(cause error) error {
	o.state = ReviewRequired
	for _, standard := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(cause, standard) {
			return errors.Join(ErrReviewRequired, standard)
		}
	}
	return ErrReviewRequired
}

// Observe reports historical state, not fresh service or kernel readiness.
func (o *Owner) Observe() (State, error) {
	if err := o.acquire(context.Background()); err != nil {
		return "", err
	}
	defer func() { <-o.gate }()
	return o.state, nil
}

func (o *Owner) acquire(ctx context.Context) error {
	if o == nil || o.original != o || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-o.gate
			return err
		}
		return nil
	default:
		return ErrBusy
	}
}

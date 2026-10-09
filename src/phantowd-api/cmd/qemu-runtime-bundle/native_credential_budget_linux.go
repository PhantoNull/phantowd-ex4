//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"
)

// Fixture orchestration only: this timer carries no identity/runtime authority.
// The original Owner and backend remain fixed; failed operations are not retried.
type nativeCredentialBudgetQEMU struct {
	parent            context.Context
	preparation       context.Context
	cancelPreparation context.CancelFunc
	enrollment        context.Context
	cancelEnrollment  context.CancelFunc
	handedOff         bool
	closed            bool
}

var errNativeCredentialBudgetQEMU = errors.New("native credential fixture phase invalid")

func newNativeCredentialBudgetQEMU(parent context.Context) (*nativeCredentialBudgetQEMU, error) {
	if parent == nil {
		return nil, errNativeCredentialBudgetQEMU
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	// Separate bounded work: preparation20 plus enrollment60 allows80s rather
	// than the old shared60s. Worker/service/stop/guest limits remain unchanged.
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	return &nativeCredentialBudgetQEMU{parent: parent, preparation: ctx, cancelPreparation: cancel}, nil
}

// Single-use phase handoff. No caller can supply a replacement context or parent.
// Late preparation and uncertain prior results refuse before any enrollment.
func (b *nativeCredentialBudgetQEMU) Enrollment(prior error) (context.Context, error) {
	if b == nil || b.parent == nil || b.preparation == nil || b.cancelPreparation == nil || b.closed || b.handedOff {
		return nil, errors.Join(errNativeCredentialBudgetQEMU, prior)
	}
	b.handedOff = true
	if err := errors.Join(prior, b.preparation.Err(), b.parent.Err()); err != nil {
		b.Close()
		return nil, err
	}
	b.cancelPreparation()
	b.enrollment, b.cancelEnrollment = context.WithTimeout(b.parent, 60*time.Second)
	if err := b.enrollment.Err(); err != nil {
		b.Close()
		return nil, err
	}
	return b.enrollment, nil
}

// A late nil result is never completion. This fence does not observe passdb,
// refresh authority, recover a journal or erase an uncertain operation's error.
func (b *nativeCredentialBudgetQEMU) CompleteEnrollment(result error) error {
	if b == nil || b.parent == nil || b.closed || !b.handedOff || b.enrollment == nil || b.cancelEnrollment == nil {
		return errors.Join(errNativeCredentialBudgetQEMU, result)
	}
	err := errors.Join(result, b.enrollment.Err(), b.parent.Err())
	b.Close()
	return err
}

func (b *nativeCredentialBudgetQEMU) Close() {
	if b == nil {
		return
	}
	b.closed = true
	if b.cancelPreparation != nil {
		b.cancelPreparation()
	}
	if b.cancelEnrollment != nil {
		b.cancelEnrollment()
	}
}

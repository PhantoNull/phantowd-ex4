//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"time"
)

func (o *Owner) Start(ctx context.Context) error {
	if err := o.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.state == ReviewRequired {
		return ErrReviewRequired
	}
	if o.state != Prepared {
		return ErrState
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := checked(ctx, func(context.Context) error { return o.backend.CheckInputs(ctx, o.candidate) }, o.backend.VerifyStopped); err != nil {
		return o.review(err)
	}
	if !o.enabled {
		o.state = Disabled
		return nil
	}
	if err := checked(ctx, o.backend.Start, o.backend.VerifyReady,
		func(context.Context) error { return o.backend.CheckInputs(ctx, o.candidate) }); err != nil {
		return o.settleReview(err)
	}
	o.state = Running
	return nil
}

func (o *Owner) Stop(ctx context.Context) error {
	if err := o.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	return o.stop(ctx)
}

func (o *Owner) stop(caller context.Context) error {
	if o.state == ReviewRequired {
		return ErrReviewRequired
	}
	if o.state == Stopped {
		return nil
	}
	if o.state != Running {
		return ErrState
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := checked(ctx, o.backend.Stop, o.backend.VerifyStopped); err != nil {
		return o.review(err)
	}
	if err := caller.Err(); err != nil {
		return o.review(err)
	}
	o.state = Stopped
	return nil
}

func (o *Owner) settleReview(cause error) error {
	// An uncertain start owns possible partial effects. Settlement never releases
	// inputs and gets a separate bounded context, not the canceled caller's.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = checked(ctx, o.backend.Stop, o.backend.VerifyStopped)
	return o.review(cause)
}

func checked(ctx context.Context, calls ...func(context.Context) error) error {
	for _, call := range calls {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := call(ctx)
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		if err != nil {
			return err
		}
	}
	return nil
}

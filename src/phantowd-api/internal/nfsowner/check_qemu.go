//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"time"
)

// Check serializes one fresh observation. It does not poll, restart or release
// inputs. The fixture backend must honor the existing cooperative deadline.
func (o *Owner) Check(ctx context.Context) error {
	if err := o.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	return o.check(ctx)
}

// check requires the original Owner gate, including throughout settlement.
func (o *Owner) check(ctx context.Context) error {
	if o.state == ReviewRequired {
		return ErrReviewRequired
	}
	if o.state != Running && o.state != Disabled {
		return ErrState
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	running := o.state == Running
	probe := o.backend.VerifyStopped
	if running {
		probe = o.backend.VerifyReady
	}
	inputs := func(ctx context.Context) error { return o.backend.CheckInputs(ctx, o.candidate) }
	if err := checked(ctx, inputs, probe, inputs); err != nil {
		if running {
			return o.settleReview(err)
		}
		return o.review(err)
	}
	return nil
}

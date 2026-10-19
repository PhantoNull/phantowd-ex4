//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"time"
)

// Supervise exclusively holds the original ready lifetime. One complete Check
// follows each fixed idle interval (1 second..1 hour); no catch-up/overlap,
// restart or input release. These are sequential observations, not a guarantee
// against transient faults or blocking callbacks. Check/settlement retain their
// existing independent five-second cooperative budgets.
//
// Pre-admission cancellation has no effects. Cancellation accepted while idle
// stops a running service independently of ctx and retains inputs for explicit
// Close; disabled policy never starts/stops a service. Cancellation during an
// admitted check still uses Check's conservative retained-review semantics.
func (o *Owner) Supervise(ctx context.Context, interval time.Duration) error {
	if interval < time.Second || interval > time.Hour {
		return ErrInvalid
	}
	s, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	if s.state == ReviewRequired {
		return ErrReviewRequired
	}
	if s.state != Running && s.state != Disabled {
		return ErrState
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.state == Running {
				if err := s.stop(context.Background()); err != nil {
					return errors.Join(ctx.Err(), err)
				}
			}
			return ctx.Err()
		case <-timer.C:
			if ctx.Err() != nil {
				// A simultaneous timer must not admit a scan after cancellation.
				continue
			}
			if err := s.check(ctx); err != nil {
				return err
			}
			timer.Reset(interval)
		}
	}
}

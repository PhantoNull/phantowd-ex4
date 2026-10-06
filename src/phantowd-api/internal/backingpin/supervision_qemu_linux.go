//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// The caller joins this explicitly owned test goroutine before any independent
// fixture teardown. No detached product monitor or new startup authority.
func startFixtureSupervisor(ctx context.Context, owner *writableOwner) (context.CancelFunc, <-chan error, error) {
	watchctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- owner.supervise(watchctx) }()
	for {
		owner.mu.Lock()
		accepted := owner.supervising
		owner.mu.Unlock()
		if accepted {
			return cancel, done, nil
		}
		select {
		case err := <-done:
			cancel()
			return nil, nil, errors.Join(errors.New("fixture supervisor not accepted"), err)
		case <-ctx.Done():
			cancel()
			// Returning a live handle obliges the caller to join, not retry launch.
			return cancel, done, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func awaitFixtureSupervisor(done <-chan error) (error, bool) {
	select {
	case err := <-done:
		return err, true
	case <-time.After(8 * time.Second):
		return errors.New("fixture supervisor did not settle"), false
	}
}

func exerciseSupervisedPolicyFixture(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend, source *naspolicystore.Owner, directory, relative, kind string, lease *mountowner.MountedVolumeSetLease) (result error) {
	if err := owner.start(ctx); err != nil {
		return err
	}
	cancel, done, err := startFixtureSupervisor(ctx, owner)
	joined := done == nil
	defer func() {
		if cancel != nil {
			cancel()
		}
		if !joined {
			settleErr, settled := awaitFixtureSupervisor(done)
			if !settled || !errors.Is(settleErr, context.Canceled) || errors.Is(settleErr, ErrReview) {
				result = errors.Join(result, settleErr)
			}
		}
	}()
	if err != nil {
		return err
	}
	for _, op := range []func() error{func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close, func() error { return owner.start(ctx) }, func() error { return owner.supervise(ctx) }} {
		if !errors.Is(op(), ErrBusy) {
			return errors.New("live supervisor not exclusive")
		}
	}
	if !errors.Is(source.Commit(ctx, 1, fixtureBackingPolicy(2, relative)), naspolicystore.ErrBusy) ||
		!errors.Is(source.Close(), naspolicystore.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) ||
		!errors.Is(owner.pin.Close(), ErrBusy) {
		return errors.New("supervision lost input claims")
	}
	switch kind {
	case "policy-supervise-cancel":
		cancel()
	case "policy-supervise-drift", "policy-supervise-uncertain":
		owner.mu.Lock()
		backend.stopFailure = kind == "policy-supervise-uncertain"
		owner.mu.Unlock()
		if err := mutateFixturePolicy(directory); err != nil {
			return err
		}
	case "policy-supervise-exit":
		if err := backend.teardown(ctx); err != nil {
			return err
		}
	default:
		return ErrInvalid
	}
	err, joined = awaitFixtureSupervisor(done)
	if !joined {
		return err
	}
	if kind == "policy-supervise-cancel" {
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReview) || owner.phase != writableClosed {
			return errors.New("accepted cancellation did not verify healthy stop")
		}
	} else if !errors.Is(err, ErrReview) || owner.phase != writableReview {
		return errors.New("supervised policy drift/exit not reviewed")
	}
	if backend.stopCalls != 1 || !backend.stopWithLiveReference || owner.supervising {
		return errors.New("supervised stop ordering or reservation")
	}
	if kind == "policy-supervise-uncertain" {
		if owner.released || owner.policy == nil || owner.file == nil || owner.pin.consumer != owner ||
			!errors.Is(source.Close(), naspolicystore.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
			return errors.New("uncertain supervisor released combined claims")
		}
		if live, err := backend.running(ctx); err != nil || !live {
			return errors.New("uncertain supervisor must retain an actual live child")
		}
	} else {
		if !owner.released || owner.policy != nil || owner.file != nil {
			return errors.New("confirmed supervisor retained/released wrong inputs")
		}
		select {
		case <-backend.done:
		default:
			return errors.New("supervisor released before actual child reap")
		}
	}
	if kind == "policy-supervise-cancel" {
		return source.Commit(ctx, 1, fixtureBackingPolicy(2, relative))
	}
	for _, op := range []func() error{func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close, func() error { return owner.start(ctx) }, func() error { return owner.supervise(ctx) }} {
		if !errors.Is(op(), ErrReview) {
			return errors.New("reviewed supervisor revived/retried")
		}
	}
	if backend.stopCalls != 1 {
		return errors.New("supervisor retried uncertain stop")
	}
	return nil
}

func emitSupervisedPolicyMarker() {
	fmt.Println("PHANTOWD_POLICY_BACKING_SUPERVISION_READY exclusive=true serial_idle_scans=true actual_consumer_uid=1000 cancellation_verified_stop=true policy_drift_review=true unexpected_exit=true uncertain_retains_policy_mount_rw=true mount_loss_supervised=true no_retry=true product_startup=false scope=disposable-qemu-only")
}

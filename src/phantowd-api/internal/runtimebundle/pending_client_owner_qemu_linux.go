//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Private fixture lifecycle, not product authority. Complete original input
// pins outlive the adapter and every possible child. No descriptors, launcher
// profile, password or backend can be replaced after construction.
type pendingClientOwnerQEMU struct {
	self    *pendingClientOwnerQEMU
	gate    chan struct{}
	inputs  *pendingClientInputsQEMU
	adapter *processowner.PendingClientQEMU

	started, settled, review, closed bool
	stopTried                        bool
	stopErr, releaseErr              error
}

func newPendingClientOwnerQEMU(ctx context.Context, client, bootstrap *Plan, clientRoot, bootstrapRoot *os.File, secret []byte) (owner *pendingClientOwnerQEMU, result error) {
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1)}
	o.self = o
	var err error
	o.inputs, err = newPendingClientInputsQEMU(ctx, client, bootstrap, clientRoot, bootstrapRoot)
	if err != nil {
		return nil, err
	}
	// Construction has no child. If cleanup is uncertain, return the retained
	// reviewed object alongside the error; never discard its remaining pins.
	defer func() {
		if result != nil {
			if o.review {
				result = errors.Join(result, ErrReviewRequired)
				return
			}
			if err := o.release(); err != nil {
				o.review, o.releaseErr = true, err
				result = errors.Join(result, ErrReviewRequired, err)
			} else {
				owner = nil
			}
		}
	}()
	rootFD, err := openBeneath(int(o.inputs.client.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return o, err
	}
	root := os.NewFile(uintptr(rootFD), "original-pending-root-read-directory")
	metadata, statErr := inspectMetadata(rootFD, unix.S_IFDIR, o.inputs.client.metadata["."].Mnt_id)
	if statErr != nil || metadata != o.inputs.client.metadata["."] {
		closeErr := root.Close()
		if closeErr != nil {
			o.review = true
		}
		return o, errors.Join(ErrMismatch, statErr, closeErr)
	}
	o.adapter, err = processowner.NewPendingClientQEMU(
		o.inputs.bootstrap.files[pendingClientBootstrapQEMU], root,
		o.inputs.client.files[pendingClientProgramQEMU], secret)
	if closeErr := root.Close(); err != nil || closeErr != nil {
		if closeErr != nil {
			o.review = true // Uncertain local close cannot release other originals.
		}
		return o, errors.Join(err, closeErr)
	}
	// The process adapter's partial metadata checks are not a content fence.
	if err := o.inputs.revalidate(ctx); err != nil {
		return o, err
	}
	return o, nil
}

func (o *pendingClientOwnerQEMU) enter(ctx context.Context) error {
	if o == nil || o.self != o || o.gate == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return processowner.ErrBusy
	}
	if o.closed {
		<-o.gate
		return ErrUnavailable
	}
	return nil
}

func (o *pendingClientOwnerQEMU) fail(cause error) error {
	o.review = true
	if o.adapter != nil && !o.stopTried {
		o.stopTried = true
		o.stopErr = o.adapter.Stop(context.Background())
	}
	return errors.Join(ErrReviewRequired, cause, o.stopErr)
}

// OPEN is telemetry only. Success does not authorize WRITE or assert the
// original server/session/object. Those independent witnesses remain required.
func (o *pendingClientOwnerQEMU) start(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review || o.started || o.releaseErr != nil || o.adapter == nil {
		return ErrReviewRequired
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return o.fail(err)
	}
	o.started = true
	if err := o.adapter.Start(ctx); err != nil {
		return o.fail(err)
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return o.fail(err)
	}
	return nil
}

func (o *pendingClientOwnerQEMU) closeClient(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review || !o.started || o.settled || o.adapter == nil {
		return ErrReviewRequired
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return o.fail(err)
	}
	if err := o.adapter.CloseClient(ctx); err != nil {
		return o.fail(err)
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return o.fail(err)
	}
	o.settled = true
	return nil
}

// Stop is containment, not successful protocol close. Even a verified local
// termination preserves review and all authority; no release/restart/retry.
func (o *pendingClientOwnerQEMU) stop(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	if err := o.enter(context.Background()); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	return o.fail(ErrReviewRequired)
}

func (o *pendingClientOwnerQEMU) close() error {
	if o == nil || o.self != o || o.gate == nil {
		return ErrUnavailable
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return processowner.ErrBusy
	}
	defer func() { <-o.gate }()
	if o.review || o.releaseErr != nil {
		return ErrReviewRequired
	}
	if o.closed {
		return nil
	}
	if o.started && !o.settled {
		return processowner.ErrBusy
	}
	if err := o.inputs.revalidate(context.Background()); err != nil {
		return o.fail(err)
	}
	if err := o.release(); err != nil {
		o.review, o.releaseErr = true, err
		return errors.Join(ErrReviewRequired, err)
	}
	o.closed = true
	return nil
}

// Only constructor rollback (no launch) or serialized terminal closure calls
// this. The concrete adapter independently proves original group absence before
// releasing any handoff pins; complete input pins are released strictly AFTER.
func (o *pendingClientOwnerQEMU) release() error {
	if o.releaseErr != nil {
		return o.releaseErr
	}
	if o.adapter != nil {
		if err := o.adapter.Close(); err != nil {
			return err
		}
		o.adapter = nil
	}
	return o.inputs.release()
}

// ProbePendingClientOwnerQEMU qualifies construction and never-started closure
// of the composition on ARM, NOT process execution, SMB or pending-I/O. The
// fixed synthetic secret is deliberately not an operator credential.
func (p *Plan) ProbePendingClientOwnerQEMU(ctx context.Context, bootstrap *Plan, clientRoot, bootstrapRoot *os.File) (result error) {
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	// Failure AFTER complete-input retention must release the never-launched
	// constructor's originals. No invalid secret is copied or transmitted.
	refused, refusalErr := newPendingClientOwnerQEMU(ctx, p, bootstrap, clientRoot, bootstrapRoot, nil)
	if refused != nil || !errors.Is(refusalErr, processowner.ErrInvalid) {
		return errors.Join(ErrMismatch, refusalErr)
	}
	if count, err := retainedFixtureFDCount(); err != nil || count != before {
		return errors.Join(ErrMismatch, err)
	}
	clientCaller, err := duplicateRoot(clientRoot)
	if err != nil {
		return err
	}
	helperCaller, err := duplicateRoot(bootstrapRoot)
	if err != nil {
		return errors.Join(err, clientCaller.Close())
	}
	value, constructErr := newPendingClientOwnerQEMU(ctx, p, bootstrap, clientCaller, helperCaller, []byte("qemu-only-not-a-credential"))
	callerErr := errors.Join(clientCaller.Close(), helperCaller.Close())
	if constructErr != nil || callerErr != nil {
		// A non-nil failed constructor may hold reviewed authority. Leave it
		// for whole disposable-guest teardown; never assume safe release.
		return errors.Join(constructErr, callerErr)
	}
	defer func() { result = errors.Join(result, value.close()) }()
	copied := *value
	if copied.start(ctx) == nil || copied.close() == nil {
		return ErrMismatch
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(value.start(canceled), context.Canceled) || value.started {
		return ErrMismatch
	}
	value.gate <- struct{}{}
	startErr, closeErr := value.start(ctx), value.close()
	<-value.gate
	if !errors.Is(startErr, processowner.ErrBusy) || !errors.Is(closeErr, processowner.ErrBusy) {
		return ErrMismatch
	}
	if err := value.inputs.revalidate(ctx); err != nil {
		return err
	}
	if err := value.close(); err != nil {
		return err
	}
	if value.start(ctx) == nil || value.closeClient(ctx) == nil || !value.closed || value.adapter != nil {
		return ErrMismatch
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.Join(ErrMismatch, err)
	}
	fmt.Println("PHANTOWD_PENDING_OWNER_READY complete_inputs=true adapter_bound=true constructor_refused=true caller_duplicate_closed=true late_rechecked=true copied_refused=true canceled_refused=true busy_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only")
	return nil
}

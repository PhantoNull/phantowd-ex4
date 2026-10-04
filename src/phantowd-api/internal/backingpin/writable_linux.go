//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"os"
	"path"
	"reflect"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"

	"golang.org/x/sys/unix"
)

// Entirely private prototype: no product opener or arbitrary callback API.
// Only package tests/QEMU supply a retained RW file and fixed trusted backend.
// Success transfers exclusive Pin/file/backend ownership; failure transfers
// nothing. This verifies an existing descriptor, it does not mint production
// mount/access/allocation/global-use/session/credential authority.
type writableBackend interface {
	start(context.Context, *os.File) error
	running(context.Context) (bool, error)
	stop(context.Context) error // Success means all borrowers are stopped/joined.
}

type writablePhase uint8

const (
	writablePrepared writablePhase = iota
	writableActive
	writableReview
	writableClosed
)

type writableOwner struct {
	nonSerializable
	mu                               sync.Mutex
	pin                              *Pin
	file                             *os.File
	backend                          writableBackend
	policy                           *naspolicystore.Lease // privately acquired; never caller-releasable
	check                            func() error          // Fixed kernel checker; state-machine tests use a private seam.
	phase                            writablePhase
	started, stopAttempted, released bool
}

func newWritableOwner(pin *Pin, file *os.File, backend writableBackend) (*writableOwner, error) {
	if pin == nil || file == nil || nilWritableBackend(backend) {
		return nil, ErrInvalid
	}
	owner := &writableOwner{pin: pin, file: file, backend: backend, phase: writablePrepared}
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.consumer != nil {
		return nil, ErrBusy
	}
	if owner.checkDescriptorLocked() != nil {
		return nil, ErrUnavailable
	}
	pin.consumer = owner
	owner.check = owner.checkBinding
	return owner, nil
}

func nilWritableBackend(backend writableBackend) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Private prototype composition, not target/access/allocation admission. It
// acquires its OWN coherent policy claim and matches one declared backing to
// the already-qualified mounted Pin. A desired target state/SecretRef is not
// launch authority. Failure transfers no Pin/file/backend and releases only the
// newly acquired policy claim; success retains all inputs through consumer stop.
func newPolicyBoundWritableOwner(ctx context.Context, pin *Pin, file *os.File, backend writableBackend, source *naspolicystore.Owner, revision uint64, backingID iscsipolicy.BackingID) (_ *writableOwner, result error) {
	if ctx == nil || pin == nil || file == nil || source == nil || backingID == "" || nilWritableBackend(backend) {
		return nil, ErrInvalid
	}
	lease, err := source.Acquire(ctx, revision)
	if err != nil {
		if errors.Is(err, naspolicystore.ErrReview) {
			return nil, ErrReview
		}
		return nil, ErrUnavailable
	}
	keep := false
	defer func() {
		if !keep && lease.Release() != nil {
			result = ErrReview
		}
	}()
	document, err := lease.Snapshot(ctx)
	if err != nil {
		return nil, ErrReview
	}
	pin.mu.Lock()
	matches := policyMatchesPin(document, backingID, pin)
	pin.mu.Unlock()
	if !matches {
		return nil, ErrInvalid
	}
	if lease.Verify(ctx) != nil {
		return nil, ErrReview
	}
	owner, err := newWritableOwner(pin, file, backend)
	if err != nil {
		return nil, err
	}
	owner.policy = lease
	keep = true
	return owner, nil
}

// Requires pin.mu. Only immutable selection is compared; metadata/descriptor
// admission is still performed by newWritableOwner. This is not registry,
// allocation or access qualification, and does not resolve symbolic secrets.
func policyMatchesPin(document naspolicy.Config, id iscsipolicy.BackingID, pin *Pin) bool {
	if document.Validate() != nil || pin.mountRoot == nil || pin.volumeID == "" {
		return false
	}
	for _, backing := range document.ISCSI.Backings {
		if backing.ID == id {
			return string(backing.VolumeID) == pin.volumeID && backing.RelativePath == path.Join(pin.directory, pin.name) &&
				backing.CapacityBytes == pin.fileIdentity.size
		}
	}
	return false
}

// Never hold the policy lock while acquiring Pin/mount locks. The consumer
// mutex serializes its own lifecycle; each source is rechecked in a bracket.
// Cooperating desired writers cannot change the revision while the claim lives.
func (o *writableOwner) checkInputs(ctx context.Context) error {
	if o.policy != nil && o.policy.Verify(ctx) != nil {
		return ErrReview
	}
	if o.check == nil || o.check() != nil {
		return ErrReview
	}
	if o.policy != nil && o.policy.Verify(ctx) != nil {
		return ErrReview
	}
	return nil
}

// Requires pin.mu. Checks happen before and after inspecting the RW descriptor.
func (o *writableOwner) checkDescriptorLocked() error {
	p := o.pin
	if _, err := p.verifyLocked(); err != nil {
		return ErrReview
	}
	id, _, err := observe(o.file, true)
	flags, flagErr := unix.FcntlInt(o.file.Fd(), unix.F_GETFL, 0)
	fdFlags, fdErr := unix.FcntlInt(o.file.Fd(), unix.F_GETFD, 0)
	if err != nil || id != p.fileIdentity || id.readOnly || flagErr != nil || fdErr != nil ||
		flags&unix.O_ACCMODE != unix.O_RDWR || flags&(unix.O_PATH|unix.O_APPEND) != 0 || fdFlags&unix.FD_CLOEXEC == 0 {
		return ErrReview
	}
	if _, err := p.verifyLocked(); err != nil {
		return ErrReview
	}
	return nil
}

func (o *writableOwner) checkBinding() error {
	o.pin.mu.Lock()
	defer o.pin.mu.Unlock()
	if o.pin.consumer != o {
		return ErrReview
	}
	return o.checkDescriptorLocked()
}

func (o *writableOwner) start(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == writableReview {
		return ErrReview
	}
	if o.phase != writablePrepared {
		if o.phase == writableActive {
			return ErrBusy
		}
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if o.checkInputs(ctx) != nil {
		return o.quarantineLocked(ctx)
	}
	o.started = true // Even a failed start may have acquired kernel/child resources.
	if o.backend.start(ctx, o.file) != nil {
		return o.quarantineLocked(ctx)
	}
	running, err := o.backend.running(ctx)
	if err != nil || !running || ctx.Err() != nil || o.checkInputs(ctx) != nil {
		return o.quarantineLocked(ctx)
	}
	o.phase = writableActive
	return nil
}

// Caller-driven observation, no monitor/restart goroutine. Any identity drift,
// unexpected exit or uncertainty makes one stop attempt before reference release.
func (o *writableOwner) observe(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == writableReview {
		return ErrReview
	}
	if o.phase == writableClosed {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if o.checkInputs(ctx) != nil {
		return o.quarantineLocked(ctx)
	}
	if o.phase == writableActive {
		running, err := o.backend.running(ctx)
		if err != nil || !running || ctx.Err() != nil || o.checkInputs(ctx) != nil {
			return o.quarantineLocked(ctx)
		}
	}
	return nil
}

func (o *writableOwner) stop(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == writableReview {
		return ErrReview
	}
	if o.phase == writableClosed {
		return nil
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if o.started {
		o.stopAttempted = true
		if o.backend.stop(ctx) != nil {
			o.phase = writableReview
			return ErrReview
		}
	}
	if o.releaseLocked() != nil {
		o.phase = writableReview
		return ErrReview
	}
	o.phase = writableClosed
	return nil
}

// Close is not an implicit stop. An uncertain stop cannot be retried or bypassed
// through close; its file/Pin remain retained for an explicit future recovery.
func (o *writableOwner) close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == writableReview {
		return ErrReview
	}
	if o.phase == writableActive || o.started && !o.stopAttempted {
		return ErrBusy
	}
	if o.phase == writableClosed {
		return nil
	}
	if o.releaseLocked() != nil {
		o.phase = writableReview
		return ErrReview
	}
	o.phase = writableClosed
	return nil
}

func (o *writableOwner) quarantineLocked(ctx context.Context) error {
	o.phase = writableReview
	if o.started {
		if o.stopAttempted {
			return ErrReview
		}
		o.stopAttempted = true
		if o.backend.stop(ctx) != nil {
			return ErrReview
		}
	}
	_ = o.releaseLocked()
	return ErrReview
}

// Data descriptor close failure deliberately retains the Pin/claim. No release
// retry is attempted: a future recovery must establish actual backend state.
func (o *writableOwner) releaseLocked() error {
	if o.released {
		return nil
	}
	if o.file == nil || o.file.Close() != nil {
		return ErrReview
	}
	o.file = nil
	o.pin.mu.Lock()
	if o.pin.consumer != o {
		o.pin.mu.Unlock()
		return ErrReview
	}
	o.pin.consumer = nil
	pinErr := o.pin.closeLocked()
	o.pin.mu.Unlock()
	if pinErr != nil {
		return ErrReview
	}
	if o.policy != nil {
		if o.policy.Release() != nil {
			return ErrReview
		}
		o.policy = nil
	}
	o.released = true
	return nil
}

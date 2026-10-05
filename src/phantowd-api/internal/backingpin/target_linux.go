//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Private, caller-owned existing references. Neither these selectors nor a
// desired LUN access mode mint data-opening/allocation/global-use authority.
type targetSelection struct {
	backingID iscsipolicy.BackingID
	pin       *Pin
	file      *os.File
}
type targetBacking struct {
	nonSerializable
	lunID     iscsipolicy.LUNID
	number    uint16
	backingID iscsipolicy.BackingID
	capacity  uint64
	blockSize uint16
	access    string
	pin       *Pin
	file      *os.File
}

// One fixed target borrower for the COMPLETE roster. Successful stop must join
// all processes/sessions/kernel credential users, not only the first LUN. The
// containing owner lends data handles; the backend must not close or replace
// them. Desired access is metadata, not an independently qualified permission.
type targetBackend interface {
	iscsicredentials.Consumer
	startTarget(context.Context, []targetBacking) error
	running(context.Context) (bool, error)
	stop(context.Context) error
}
type targetBackendAdapter struct {
	backend  targetBackend
	backings []targetBacking
}

// Ignore mount ID here: two bind views must not conceal the same inode/device
// behind different Pins or descriptors. This remains metadata alias refusal,
// not physical extent/allocation or complete global-use admission.
func distinctTargetObjects(backings []targetBacking) bool {
	type object struct {
		major, minor uint32
		inode        uint64
	}
	seen := map[object]bool{}
	for _, backing := range backings {
		if backing.pin == nil {
			return false
		}
		backing.pin.mu.Lock()
		id := backing.pin.fileIdentity
		backing.pin.mu.Unlock()
		key := object{id.major, id.minor, id.inode}
		if key.inode == 0 || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (b *targetBackendAdapter) start(ctx context.Context, _ *os.File) error {
	return b.backend.startTarget(ctx, append([]targetBacking(nil), b.backings...))
}
func (b *targetBackendAdapter) running(ctx context.Context) (bool, error) {
	return b.backend.running(ctx)
}
func (b *targetBackendAdapter) stop(ctx context.Context) error { return b.backend.stop(ctx) }

// Pure complete membership/alias planning. Real descriptor/kernel checks are
// separate and mandatory. No partial, positional, inferred or foreign roster.
func planTarget(document naspolicy.Config, id iscsipolicy.TargetID, inputs []targetSelection) ([]targetBacking, error) {
	if !knownTargetUseAllowed(document, id) || len(inputs) == 0 || len(inputs) > iscsipolicy.MaxLUNs {
		return nil, ErrInvalid
	}
	var target *iscsipolicy.Target
	for i := range document.ISCSI.Targets {
		if document.ISCSI.Targets[i].ID == id {
			target = &document.ISCSI.Targets[i]
		}
	}
	if target == nil || len(inputs) != len(target.LUNs) {
		return nil, ErrInvalid
	}
	selected := map[iscsipolicy.BackingID]targetSelection{}
	pins, files := map[*Pin]bool{}, map[uintptr]bool{}
	for _, input := range inputs {
		if input.pin == nil || input.file == nil || input.backingID == "" || pins[input.pin] || selected[input.backingID].pin != nil {
			return nil, ErrInvalid
		}
		fd := input.file.Fd()
		if fd == ^uintptr(0) || files[fd] {
			return nil, ErrInvalid
		}
		selected[input.backingID] = input
		pins[input.pin], files[fd] = true, true
	}
	definitions := map[iscsipolicy.BackingID]iscsipolicy.Backing{}
	for _, backing := range document.ISCSI.Backings {
		definitions[backing.ID] = backing
	}
	result := make([]targetBacking, 0, len(inputs))
	for _, lun := range target.LUNs {
		input, ok := selected[lun.BackingID]
		if !ok {
			return nil, ErrInvalid
		}
		backing := definitions[lun.BackingID]
		result = append(result, targetBacking{lunID: lun.ID, number: lun.Number, backingID: lun.BackingID,
			capacity: backing.CapacityBytes, blockSize: backing.BlockSize, access: lun.Access, pin: input.pin, file: input.file})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].number < result[j].number })
	return result, nil
}

// Reuses writableOwner's state machine, supervision and terminal review. It
// privately claims one coherent policy, one credential bundle and every selected
// Pin/file before execution. Input order is irrelevant; backend roster is sorted
// by explicit LUN number. Only one Pin lock is held at a time, including rollback;
// there is no caller-dependent multiple-Pin lock order. Provisional claims block
// Pin.Close during admission; failed admission returns all caller resources
// untouched (apart from any already-observed sticky Pin/source review).
// No product opener, LIO/configfs, listener, HTTP or automatic recovery.
func newTargetWritableOwner(ctx context.Context, inputs []targetSelection, backend targetBackend,
	source *naspolicystore.Owner, revision uint64, secrets *iscsicredentials.Owner, secretRevision uint64, id iscsipolicy.TargetID) (_ *writableOwner, result error) {
	if ctx == nil || source == nil || secrets == nil || backend == nil {
		return nil, ErrInvalid
	}
	v := reflect.ValueOf(backend)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		if v.IsNil() {
			return nil, ErrInvalid
		}
	}
	policy, err := source.Acquire(ctx, revision)
	if err != nil {
		if errors.Is(err, naspolicystore.ErrReview) {
			return nil, ErrReview
		}
		return nil, ErrUnavailable
	}
	var credentials *iscsicredentials.Bundle
	var owner *writableOwner
	var claimed []*Pin
	keep := false
	defer func() {
		if keep {
			return
		}
		for i := len(claimed) - 1; i >= 0; i-- {
			pin := claimed[i]
			pin.mu.Lock()
			if pin.consumer != owner {
				pin.mu.Unlock()
				owner.phase = writableReview
				result = ErrReview
				return // Retain sources for an impossible/uncertain ownership loss.
			}
			pin.consumer = nil
			pin.mu.Unlock()
		}
		if credentials != nil && credentials.Release() != nil {
			result = ErrReview
		}
		if policy.Release() != nil {
			result = ErrReview
		}
	}()
	document, err := policy.Snapshot(ctx)
	if err != nil {
		return nil, ErrReview
	}
	backings, err := planTarget(document, id, inputs)
	if err != nil {
		return nil, err
	}
	for _, backing := range backings {
		backing.pin.mu.Lock()
		matches := policyMatchesPin(document, backing.backingID, backing.pin)
		backing.pin.mu.Unlock()
		if !matches {
			return nil, ErrInvalid
		}
	}
	if !distinctTargetObjects(backings) {
		return nil, ErrInvalid
	}
	credentials, err = secrets.Acquire(ctx, secretRevision, document, id, backend)
	if err != nil {
		if errors.Is(err, iscsicredentials.ErrReview) {
			return nil, ErrReview
		}
		return nil, ErrUnavailable
	}
	owner = &writableOwner{pin: backings[0].pin, file: backings[0].file, group: backings, phase: writablePrepared,
		policy: policy, credentials: credentials, backend: &targetBackendAdapter{backend: backend, backings: backings}}
	owner.check = owner.checkTargetBinding
	for _, backing := range backings {
		pin := backing.pin
		pin.mu.Lock()
		if pin.consumer != nil {
			pin.mu.Unlock()
			return nil, ErrBusy
		}
		probe := &writableOwner{pin: pin, file: backing.file}
		if probe.checkDescriptorLocked() != nil {
			pin.mu.Unlock()
			return nil, ErrUnavailable
		}
		pin.consumer = owner
		claimed = append(claimed, pin)
		pin.mu.Unlock()
	}
	if owner.checkInputs(ctx) != nil {
		return nil, ErrReview
	}
	keep = true
	return owner, nil
}

func (o *writableOwner) checkTargetBinding() error {
	if len(o.group) == 0 {
		return ErrReview
	}
	for _, backing := range o.group {
		pin := backing.pin
		pin.mu.Lock()
		probe := &writableOwner{pin: pin, file: backing.file}
		ok := pin.consumer == o && probe.checkDescriptorLocked() == nil
		pin.mu.Unlock()
		if !ok {
			return ErrReview
		}
	}
	return nil
}

// Called only after independently confirmed WHOLE-backend teardown. All data
// closes must succeed before ANY Pin is released. A close failure is never
// retried; earlier successfully closed FDs stay closed, and all remaining Pin/
// policy/credential claims remain for review. Source release is shared with the
// singleton path and only follows complete metadata/mount-root closure.
func (o *writableOwner) releaseTargetLocked() error {
	for i := range o.group {
		backing := &o.group[i]
		if backing.file == nil || backing.file.Close() != nil {
			return ErrReview
		}
		backing.file = nil
		if i == 0 {
			o.file = nil
		}
	}
	for _, backing := range o.group {
		pin := backing.pin
		pin.mu.Lock()
		if pin.consumer != o {
			pin.mu.Unlock()
			return ErrReview
		}
		pin.consumer = nil
		err := pin.closeLocked()
		pin.mu.Unlock()
		if err != nil {
			return ErrReview
		}
	}
	return o.releaseSourcesLocked()
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ServiceSharePinsQEMU retains the original attached share objects and prevents
// handoff/roster teardown. It is confined to disposable QEMU qualification.
// The trusted consumer must stop/reap all descendants and close every copied
// input before Close; Close alone cannot prove settlement of external aliases.
// Lock order is pin -> handoff -> complete roster -> canonical volume Owners.
type ServiceSharePinsQEMU struct {
	sharePinNonSerializableQEMU
	mu             sync.Mutex
	handoff        *ServiceHandoff
	roots          []shareRootQEMU
	closed, review bool
	closeUncertain bool
}

type shareRootQEMU struct {
	id       string
	readOnly bool
	identity handoffIdentity
	file     *os.File
}

// ServiceShareDescriptorQEMU is an independent caller-owned O_PATH descriptor
// for exactly one declared share, never the whole handoff/volume root. It is
// input to a future fixed native launch profile, not service authorization.
type ServiceShareDescriptorQEMU struct {
	ShareID  string
	ReadOnly bool
	File     *os.File
}

type sharePinNonSerializableQEMU struct{}

func (sharePinNonSerializableQEMU) MarshalJSON() ([]byte, error) { return nil, ErrHandoffInvalid }
func (*sharePinNonSerializableQEMU) UnmarshalJSON([]byte) error  { return ErrHandoffInvalid }
func (ServiceShareDescriptorQEMU) MarshalJSON() ([]byte, error)  { return nil, ErrHandoffInvalid }
func (*ServiceShareDescriptorQEMU) UnmarshalJSON([]byte) error   { return ErrHandoffInvalid }

// RetainShareRootsQEMU consumes lifecycle control of one active, otherwise
// unclaimed handoff. Fresh complete verification brackets descriptor retention.
// No recursive tree clone is supplied. A late uncertain cleanup returns the
// quarantined handle AND an error; callers must retain it, never retry cleanup.
func (h *ServiceHandoff) RetainShareRootsQEMU() (*ServiceSharePinsQEMU, error) {
	if h == nil || runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrHandoffInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return nil, ErrHandoffInvalid
	}
	if err := h.Verify(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != ServiceHandoffActive || h.resourcesClosed || h.runtimeReserved || h.isolatedPins != 0 ||
		h.verifyRestrictedContentsLocked() != nil || h.verifyBoundPathsLocked() != nil {
		return nil, ErrHandoffReview
	}
	p := &ServiceSharePinsQEMU{handoff: h}
	fail := func(cause error) (*ServiceSharePinsQEMU, error) {
		h.reviewRequired, h.state = true, ServiceHandoffReview
		if err := p.closeInputs(); err != nil {
			p.review, p.closeUncertain = true, true
			h.runtimeReserved, h.isolatedReserved, h.isolatedPins = true, true, 1
			h.reviewRequired, h.state = true, ServiceHandoffReview
			return p, errors.Join(ErrHandoffReview, cause, err)
		}
		return nil, cause
	}
	for _, member := range h.members {
		file, err := openHandoffTarget(int(h.root.Fd()), member.shareID)
		if err != nil {
			return fail(ErrHandoffReview)
		}
		p.roots = append(p.roots, shareRootQEMU{id: member.shareID, readOnly: member.readOnly,
			identity: member.bound, file: file})
		if err := verifyShareRootQEMU(file, member.bound); err != nil {
			return fail(err)
		}
	}
	if _, err := h.lease.Verify(); err != nil || h.verifyBoundPathsLocked() != nil ||
		h.verifyRestrictedContentsLocked() != nil {
		h.reviewRequired, h.state = true, ServiceHandoffReview
		return fail(ErrHandoffReview)
	}
	h.runtimeReserved, h.isolatedReserved, h.isolatedPins = true, true, 1
	return p, nil
}

func verifyShareRootQEMU(file *os.File, expected handoffIdentity) error {
	if file == nil {
		return ErrHandoffReview
	}
	identity, err := handoffIdentityForFD(int(file.Fd()))
	var fs unix.Statfs_t
	const protected = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if err != nil || identity != expected || !identity.mountRoot ||
		unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Flags&protected != protected {
		return ErrHandoffReview
	}
	return nil
}

func (p *ServiceSharePinsQEMU) verify() error {
	if p.closed {
		return ErrHandoffUnavailable
	}
	if p.review || p.closeUncertain || p.handoff.Verify() != nil {
		p.review = true
		return ErrHandoffReview
	}
	for _, root := range p.roots {
		if err := verifyShareRootQEMU(root.file, root.identity); err != nil {
			p.review = true
			return err
		}
	}
	return nil
}

func (p *ServiceSharePinsQEMU) Verify() error {
	if p == nil || p.handoff == nil {
		return ErrHandoffInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.verify()
}

// VerifyDeclaredRoots compares the complete requested set with the exact
// declaration retained by the live handoff. It cannot authorize services or
// validate identity/policy freshness. A mismatching caller request refuses
// without changing a healthy pin; actual source drift still enters review.
func (p *ServiceSharePinsQEMU) VerifyDeclaredRoots(required []ServiceShare) error {
	if p == nil || p.handoff == nil {
		return ErrHandoffInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.verify(); err != nil {
		return err
	}
	h := p.handoff
	h.mu.Lock()
	defer h.mu.Unlock()
	if !sameDeclaredRootsQEMU(required, h.required) {
		return ErrHandoffInvalid
	}
	return nil
}

func sameDeclaredRootsQEMU(required, actual []ServiceShare) bool {
	if len(required) == 0 || len(required) != len(actual) {
		return false
	}
	// Never sort caller-owned policy or the original handoff declaration.
	required, actual = slices.Clone(required), slices.Clone(actual)
	compare := func(a, b ServiceShare) int { return strings.Compare(a.ID, b.ID) }
	slices.SortFunc(required, compare)
	slices.SortFunc(actual, compare)
	for index := range required {
		if !validHandoffShareID(required[index].ID) || required[index] != actual[index] ||
			(index > 0 && required[index-1].ID == required[index].ID) {
			return false
		}
	}
	return true
}

// DuplicateRoots duplicates only already-retained original descriptors.
// Source pathname restoration cannot revive a reviewed pin or select new data.
func (p *ServiceSharePinsQEMU) DuplicateRoots() ([]ServiceShareDescriptorQEMU, error) {
	if p == nil || p.handoff == nil {
		return nil, ErrHandoffInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.verify(); err != nil {
		return nil, err
	}
	var result []ServiceShareDescriptorQEMU
	fail := func(cause error) ([]ServiceShareDescriptorQEMU, error) {
		for _, input := range result {
			if err := input.File.Close(); err != nil {
				p.closeUncertain, p.review = true, true
				// Keep the uncertain object owned, not hidden behind nil output.
				p.roots = append(p.roots, shareRootQEMU{file: input.File})
			}
		}
		return nil, cause
	}
	for _, root := range p.roots {
		fd, err := unix.FcntlInt(root.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			p.review = true
			return fail(ErrHandoffReview)
		}
		result = append(result, ServiceShareDescriptorQEMU{ShareID: root.id, ReadOnly: root.readOnly,
			File: os.NewFile(uintptr(fd), "original-declared-share-input")})
	}
	if err := p.verify(); err != nil {
		return fail(err)
	}
	return result, nil
}

func (p *ServiceSharePinsQEMU) closeInputs() error {
	for index := range p.roots {
		if file := p.roots[index].file; file != nil {
			if err := file.Close(); err != nil {
				return err
			}
			p.roots[index].file = nil
		}
	}
	return nil
}

// Close is explicit input release after the trusted consumer's verified stop
// and copied-FD closure. Any uncertainty preserves the handoff and roster pin.
func (p *ServiceSharePinsQEMU) Close() error {
	if p == nil || p.handoff == nil {
		return ErrHandoffInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closeUncertain {
		return ErrHandoffReview
	}
	if !p.closed {
		h := p.handoff
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.isolatedPins != 1 || p.closeInputs() != nil {
			p.review, p.closeUncertain = true, true
			h.reviewRequired, h.state = true, ServiceHandoffReview
			return ErrHandoffReview
		}
		h.isolatedPins--
		p.closed = true
	}
	if p.review {
		return ErrHandoffReview
	}
	return nil
}

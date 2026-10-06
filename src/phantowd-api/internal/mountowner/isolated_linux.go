//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// IsolatedServiceRuntime consumes one prepared handoff as the exact grant-only
// root of one fixed static, non-root process. No runtime files/interpreters,
// product storage qualification, Samba impersonation or kernel NFS authority.
type IsolatedServiceRuntime struct {
	runtime *ServiceRuntime
	process *isolatedHandoffProcess
}

type isolatedHandoffProcess struct {
	handoff  *ServiceHandoff
	spec     processowner.Spec
	launcher string
	pin      *isolatedRootPin
	owner    *processowner.IsolatedOwner
	diagMu   sync.Mutex
	diag     *processowner.IsolatedOwner
}

type isolatedRootPin struct {
	handoff *ServiceHandoff
	file    *os.File
	closed  bool
}

// NewIsolatedServiceRuntime starts/mounts nothing. Every declared share in the
// dedicated handoff belongs to this one service; create separate handoffs for
// distinct grants. Inputs are copied once and not selectable through HTTP/RPC.
func NewIsolatedServiceRuntime(handoff *ServiceHandoff, spec processowner.Spec, launcher string) (*IsolatedServiceRuntime, error) {
	if handoff == nil || !filepath.IsAbs(launcher) || filepath.Clean(launcher) != launcher ||
		strings.ContainsRune(launcher, '\x00') {
		return nil, ErrServiceRuntimeInvalid
	}
	validated, err := processowner.NewSet([]processowner.MemberSpec{{Name: "isolated-service", Process: spec}})
	if err != nil || !validated.AllMembersRunAsNonRootWithGroup(handoff.serviceGroupID) {
		return nil, ErrServiceRuntimeInvalid
	}
	fixed := spec
	fixed.Args = slices.Clone(spec.Args)
	credentials := *spec.RunAs
	credentials.SupplementaryGIDs = slices.Clone(credentials.SupplementaryGIDs)
	fixed.RunAs = &credentials
	handoff.mu.Lock()
	if handoff.state != ServiceHandoffPrepared || handoff.resourcesClosed || handoff.runtimeReserved {
		handoff.mu.Unlock()
		return nil, ErrServiceRuntimeInvalid
	}
	handoff.runtimeReserved, handoff.isolatedReserved = true, true
	handoff.mu.Unlock()
	process := &isolatedHandoffProcess{handoff: handoff, spec: fixed, launcher: launcher}
	runtime, err := newServiceRuntime(handoff, process)
	if err != nil {
		return nil, err
	}
	return &IsolatedServiceRuntime{runtime: runtime, process: process}, nil
}

func (IsolatedServiceRuntime) MarshalJSON() ([]byte, error) {
	return nil, errors.New("isolated service runtime is internal and not serializable")
}

func (*IsolatedServiceRuntime) UnmarshalJSON([]byte) error {
	return errors.New("isolated service runtime cannot be deserialized")
}

func (r *IsolatedServiceRuntime) Start(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || r.runtime == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeUnavailable
	}
	return r.runtime.Start(ctx)
}

func (r *IsolatedServiceRuntime) Stop(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || r.runtime == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeUnavailable
	}
	return r.runtime.Stop(ctx)
}

func (r *IsolatedServiceRuntime) Observe(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || r.runtime == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeUnavailable
	}
	return r.runtime.Observe(ctx)
}

// Diagnostics is bounded trusted in-process evidence, not a redacted response.
// Its independent mutex permits the fixed readiness callback to inspect it.
func (r *IsolatedServiceRuntime) Diagnostics() []byte {
	if r == nil || r.process == nil {
		return nil
	}
	r.process.diagMu.Lock()
	owner := r.process.diag
	r.process.diagMu.Unlock()
	if owner == nil {
		return nil
	}
	return owner.Diagnostics()
}

func isolatedSetSnapshot(process processowner.Snapshot) processowner.SetSnapshot {
	return processowner.SetSnapshot{State: process.State, Generation: process.Generation,
		Members: []processowner.MemberSnapshot{{Name: "isolated-service", Process: process}}}
}

func (p *isolatedHandoffProcess) Start(ctx context.Context) (processowner.SetSnapshot, error) {
	stopped := processowner.Snapshot{State: processowner.StateStopped}
	pin, err := p.handoff.pinIsolatedRoot()
	if err != nil {
		return isolatedSetSnapshot(stopped), err
	}
	p.pin = pin
	p.owner, err = processowner.NewIsolated(p.spec, processowner.Isolation{
		LauncherExecutable: p.launcher, Root: pin.file,
	})
	if err != nil {
		if releaseErr := pin.release(); releaseErr != nil {
			stopped.State = processowner.StateReviewRequired
			return isolatedSetSnapshot(stopped), errors.Join(processowner.ErrReviewRequired, err, releaseErr)
		}
		p.pin = nil
		return isolatedSetSnapshot(stopped), err
	}
	p.diagMu.Lock()
	p.diag = p.owner
	p.diagMu.Unlock()
	snapshot, err := p.owner.Start(ctx)
	if err != nil && snapshot.State == processowner.StateStopped && snapshot.PID == 0 {
		if releaseErr := p.releaseInputs(); releaseErr != nil {
			snapshot.State = processowner.StateReviewRequired
			return isolatedSetSnapshot(snapshot), errors.Join(processowner.ErrReviewRequired, err, releaseErr)
		}
	}
	return isolatedSetSnapshot(snapshot), err
}

func (p *isolatedHandoffProcess) Observe(ctx context.Context) (processowner.SetSnapshot, error) {
	if p.owner == nil {
		return processowner.SetSnapshot{}, processowner.ErrUnavailable
	}
	snapshot, err := p.owner.Observe(ctx)
	return isolatedSetSnapshot(snapshot), err
}

func (p *isolatedHandoffProcess) Stop(ctx context.Context) (processowner.SetSnapshot, error) {
	if p.owner == nil {
		return processowner.SetSnapshot{State: processowner.StateStopped}, nil
	}
	snapshot, err := p.owner.Stop(ctx)
	if err == nil && snapshot.State == processowner.StateStopped && snapshot.PID == 0 {
		if releaseErr := p.releaseInputs(); releaseErr != nil {
			snapshot.State = processowner.StateReviewRequired
			return isolatedSetSnapshot(snapshot), errors.Join(processowner.ErrReviewRequired, releaseErr)
		}
	}
	return isolatedSetSnapshot(snapshot), err
}

func (p *isolatedHandoffProcess) releaseInputs() error {
	if p.owner != nil {
		if err := p.owner.Close(); err != nil {
			return err
		}
	}
	if p.pin != nil {
		if err := p.pin.release(); err != nil {
			return err
		}
		p.pin = nil
	}
	return nil
}

// The pin prevents direct handoff teardown until the process owner has
// confirmed stop/reap and closed its independently copied root descriptor.
func (h *ServiceHandoff) pinIsolatedRoot() (*isolatedRootPin, error) {
	if err := h.Verify(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.isolatedReserved || h.isolatedPins != 0 || h.state != ServiceHandoffActive ||
		h.resourcesClosed || h.verifyBoundPathsLocked() != nil {
		return nil, ErrHandoffReview
	}
	evidence, err := h.lease.Verify()
	if err != nil || evidence.Generation() != h.evidence.Generation() || evidence.Fingerprint() != h.evidence.Fingerprint() {
		h.reviewRequired, h.state = true, ServiceHandoffReview
		return nil, ErrHandoffReview
	}
	fd, err := unix.Openat2(int(h.root.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrHandoffUnavailable
	}
	identity, err := handoffIdentityForFD(fd)
	if err != nil || identity != h.rootIdentity {
		_ = unix.Close(fd)
		return nil, ErrHandoffReview
	}
	h.isolatedPins++
	return &isolatedRootPin{handoff: h, file: os.NewFile(uintptr(fd), "fixed-isolated-handoff-root")}, nil
}

func (pin *isolatedRootPin) release() error {
	h := pin.handoff
	h.mu.Lock()
	defer h.mu.Unlock()
	if pin.closed || h.isolatedPins != 1 {
		return ErrHandoffReview
	}
	pin.closed = true
	if err := pin.file.Close(); err != nil {
		h.reviewRequired, h.state = true, ServiceHandoffReview
		return ErrHandoffReview
	}
	h.isolatedPins--
	return nil
}

// Exact bounded directory enumeration is the initial grant-only manifest.
// No undeclared files, device nodes, runtime directories or hidden grants.
func (h *ServiceHandoff) verifyRestrictedContentsLocked() error {
	fd, err := unix.Openat2(int(h.root.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return ErrHandoffReview
	}
	file := os.NewFile(uintptr(fd), "bounded-service-root-census")
	entries, readErr := file.ReadDir(len(h.members) + 1)
	remaining, eofErr := file.ReadDir(1)
	closeErr := file.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil ||
		len(h.members) == 0 || len(entries) != len(h.members) || len(remaining) != 0 || !errors.Is(eofErr, io.EOF) {
		return ErrHandoffReview
	}
	allowed := make(map[string]bool, len(h.members))
	for _, member := range h.members {
		allowed[member.shareID] = true
	}
	for _, entry := range entries {
		if !entry.IsDir() || !allowed[entry.Name()] {
			return ErrHandoffReview
		}
	}
	return nil
}

//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

var (
	ErrServiceRuntimeInvalid     = errors.New("invalid storage-backed service runtime")
	ErrServiceRuntimeUnavailable = errors.New("storage-backed service runtime unavailable")
	ErrServiceRuntimeReview      = errors.New("storage-backed service runtime requires review")
)

type ServiceRuntimeState string

const (
	ServiceRuntimePrepared ServiceRuntimeState = "prepared"
	ServiceRuntimeStarting ServiceRuntimeState = "starting"
	ServiceRuntimeReady    ServiceRuntimeState = "ready"
	ServiceRuntimeStopping ServiceRuntimeState = "stopping"
	ServiceRuntimeReview   ServiceRuntimeState = "review-required"
	ServiceRuntimeStopped  ServiceRuntimeState = "stopped"
)

type serviceRuntimeHandoff interface {
	Mount(context.Context) (ServicePaths, error)
	Bindings() ([]ServicePathBinding, error)
	Verify() error
	Close() error
}

type serviceRuntimeProcesses interface {
	Start(context.Context) (processowner.SetSnapshot, error)
	Observe(context.Context) (processowner.SetSnapshot, error)
	Stop(context.Context) (processowner.SetSnapshot, error)
}

// ServiceRuntime orders one fixed process set around one storage handoff. Its
// caller must invoke Observe at a bounded cadence while services run; this
// object does not create an implicit monitor goroutine or restart processes.
type ServiceRuntime struct {
	mu               sync.Mutex
	handoff          serviceRuntimeHandoff
	processes        serviceRuntimeProcesses
	state            ServiceRuntimeState
	processesStarted bool
	stopAttempted    bool
	closeAttempted   bool
}

// NewServiceRuntime constructs the internal coordinator for an already-fixed
// handoff and process set. It launches no process and performs no mount.
func NewServiceRuntime(handoff *ServiceHandoff, processes *processowner.Set) (*ServiceRuntime, error) {
	if handoff == nil || processes == nil ||
		!processes.AllMembersRunAsNonRootWithGroup(handoff.serviceGroupID) {
		return nil, ErrServiceRuntimeInvalid
	}
	handoff.mu.Lock()
	claimed := handoff.runtimeReserved
	if !claimed {
		handoff.runtimeReserved = true
	}
	handoff.mu.Unlock()
	if claimed {
		return nil, ErrServiceRuntimeInvalid
	}
	return newServiceRuntime(handoff, processes)
}

func newServiceRuntime(handoff serviceRuntimeHandoff, processes serviceRuntimeProcesses) (*ServiceRuntime, error) {
	if handoff == nil || processes == nil {
		return nil, ErrServiceRuntimeInvalid
	}
	return &ServiceRuntime{handoff: handoff, processes: processes, state: ServiceRuntimePrepared}, nil
}

// Start mounts and verifies the complete roster, obtains all service-path
// bindings, then starts the fixed process set. It verifies storage again after
// all readiness probes pass. Any post-start uncertainty stops processes once;
// the handoff is closed only when processowner confirms every child stopped.
func (r *ServiceRuntime) Start(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || ctx == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != ServiceRuntimePrepared {
		return r.state, r.stateErrorLocked()
	}
	r.state = ServiceRuntimeStarting
	if _, err := r.handoff.Mount(ctx); err != nil {
		return r.finishUnstartedLocked(err)
	}
	bindings, err := r.handoff.Bindings()
	if err != nil || !validServiceBindings(bindings) {
		if err == nil {
			err = ErrServiceRuntimeInvalid
		}
		return r.finishUnstartedLocked(err)
	}
	if err := r.handoff.Verify(); err != nil {
		return r.finishUnstartedLocked(err)
	}
	snapshot, startErr := r.processes.Start(ctx)
	if startErr != nil {
		if snapshot.State == processowner.StateStopped && !errors.Is(startErr, processowner.ErrReviewRequired) {
			return r.finishUnstartedLocked(startErr)
		}
		r.state = ServiceRuntimeReview
		return r.state, errors.Join(ErrServiceRuntimeReview, startErr)
	}
	r.processesStarted = true
	if snapshot.State != processowner.StateReady {
		return r.stopForReviewLocked(ctx, processowner.ErrUnavailable)
	}
	if err := r.handoff.Verify(); err != nil {
		return r.stopForReviewLocked(ctx, err)
	}
	r.state = ServiceRuntimeReady
	return r.state, nil
}

// Observe revalidates storage before process state. If source or handoff
// identity changes, it stops consumers before attempting exact handoff
// teardown. A failed/uncertain stop retains the mount lease for review.
func (r *ServiceRuntime) Observe(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || ctx == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != ServiceRuntimeReady {
		return r.state, r.stateErrorLocked()
	}
	if err := r.handoff.Verify(); err != nil {
		return r.stopForReviewLocked(ctx, err)
	}
	snapshot, err := r.processes.Observe(ctx)
	if errors.Is(err, processowner.ErrReviewRequired) || snapshot.State == processowner.StateReviewRequired {
		return r.stopForReviewLocked(ctx, err)
	}
	if err != nil {
		return r.state, err
	}
	if snapshot.State != processowner.StateReady {
		return r.stopForReviewLocked(ctx, processowner.ErrUnavailable)
	}
	return r.state, nil
}

// Stop stops the full fixed process set before closing its handoff. A stop or
// teardown error is terminal for this runtime: no second stop, unmount, or
// automatic restart is attempted.
func (r *ServiceRuntime) Stop(ctx context.Context) (ServiceRuntimeState, error) {
	if r == nil || ctx == nil {
		return ServiceRuntimeReview, ErrServiceRuntimeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == ServiceRuntimeStopped {
		return r.state, nil
	}
	if r.state == ServiceRuntimeReview {
		return r.state, ErrServiceRuntimeReview
	}
	if r.state != ServiceRuntimePrepared && r.state != ServiceRuntimeReady {
		return r.state, ErrServiceRuntimeUnavailable
	}
	r.state = ServiceRuntimeStopping
	return r.stopAndCloseLocked(ctx)
}

func (r *ServiceRuntime) State() ServiceRuntimeState {
	if r == nil {
		return ServiceRuntimeReview
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *ServiceRuntime) finishUnstartedLocked(cause error) (ServiceRuntimeState, error) {
	closeErr := r.closeHandoffOnceLocked()
	if closeErr != nil {
		r.state = ServiceRuntimeReview
		return r.state, errors.Join(ErrServiceRuntimeReview, cause, closeErr)
	}
	r.state = ServiceRuntimeStopped
	return r.state, cause
}

func (r *ServiceRuntime) stopForReviewLocked(ctx context.Context, cause error) (ServiceRuntimeState, error) {
	if r.stopAttempted {
		r.state = ServiceRuntimeReview
		return r.state, errors.Join(ErrServiceRuntimeReview, cause)
	}
	if r.processesStarted {
		r.stopAttempted = true
		snapshot, stopErr := r.processes.Stop(ctx)
		if stopErr != nil || snapshot.State != processowner.StateStopped {
			r.state = ServiceRuntimeReview
			return r.state, errors.Join(ErrServiceRuntimeReview, cause, stopErr)
		}
		r.processesStarted = false
	}
	r.stopAttempted = true
	closeErr := r.closeHandoffOnceLocked()
	r.state = ServiceRuntimeReview
	return r.state, errors.Join(ErrServiceRuntimeReview, cause, closeErr)
}

func (r *ServiceRuntime) stopAndCloseLocked(ctx context.Context) (ServiceRuntimeState, error) {
	if r.processesStarted {
		if r.stopAttempted {
			r.state = ServiceRuntimeReview
			return r.state, ErrServiceRuntimeReview
		}
		r.stopAttempted = true
		snapshot, err := r.processes.Stop(ctx)
		if err != nil || snapshot.State != processowner.StateStopped {
			r.state = ServiceRuntimeReview
			return r.state, errors.Join(ErrServiceRuntimeReview, err)
		}
		r.processesStarted = false
	}
	r.stopAttempted = true
	closeErr := r.closeHandoffOnceLocked()
	if closeErr != nil {
		r.state = ServiceRuntimeReview
		return r.state, errors.Join(ErrServiceRuntimeReview, closeErr)
	}
	r.state = ServiceRuntimeStopped
	return r.state, nil
}

func (r *ServiceRuntime) closeHandoffOnceLocked() error {
	if r.closeAttempted {
		return ErrServiceRuntimeReview
	}
	r.closeAttempted = true
	return r.handoff.Close()
}

func (r *ServiceRuntime) stateErrorLocked() error {
	if r.state == ServiceRuntimeReview {
		return ErrServiceRuntimeReview
	}
	return ErrServiceRuntimeUnavailable
}

func validServiceBindings(bindings []ServicePathBinding) bool {
	if len(bindings) == 0 {
		return false
	}
	ids := make([]string, 0, len(bindings))
	paths := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !validHandoffShareID(binding.ShareID) || !validVolumeID(binding.VolumeID) ||
			!validHandoffRelativePath(binding.RelativePath) || !filepath.IsAbs(binding.Path) ||
			filepath.Clean(binding.Path) != binding.Path || filepath.Base(binding.Path) != binding.ShareID ||
			binding.SourceMountID == 0 || binding.DeviceMajor == 0 {
			return false
		}
		if _, exists := paths[binding.Path]; exists {
			return false
		}
		paths[binding.Path] = struct{}{}
		ids = append(ids, binding.ShareID)
	}
	slices.Sort(ids)
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			return false
		}
	}
	return true
}

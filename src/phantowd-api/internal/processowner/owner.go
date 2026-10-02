// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package processowner provides internal owners for fixed foreground service
// processes and ordered process sets. It does not adopt arbitrary processes or
// persist service state. Callers must supply fixed commands and service-
// specific readiness probes; raw diagnostics are trusted in-process data and
// must never be exposed directly through HTTP or RPC.
package processowner

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalid        = errors.New("invalid managed process request")
	ErrBusy           = errors.New("managed process owner busy")
	ErrAlreadyRunning = errors.New("managed process already owned")
	ErrNotReady       = errors.New("managed process did not become ready")
	ErrProcessExited  = errors.New("managed process exited before readiness")
	ErrReviewRequired = errors.New("managed process requires review")
	ErrUnavailable    = errors.New("managed process unavailable")
)

type State string

const (
	StateStopped        State = "stopped"
	StateStarting       State = "starting"
	StateReady          State = "ready"
	StateStopping       State = "stopping"
	StateReviewRequired State = "review-required"
)

// ReadinessProbe returns ready only when the service can perform its bounded,
// service-specific health check. A failed-but-retryable probe must return
// (false, nil); an error aborts startup. Probes must honor ctx and must not
// re-enter the same Owner.
type ReadinessProbe func(context.Context) (ready bool, err error)

// Spec is an internal fixed launch description, not an HTTP/RPC input. The
// owner validates and pins Executable before launch, passes a minimal fixed
// environment, and creates a new process group for the child.
type Spec struct {
	Executable    string
	Args          []string
	Ready         ReadinessProbe
	ReadyTimeout  time.Duration
	ProbeInterval time.Duration
	StopTimeout   time.Duration
}

type Snapshot struct {
	State                State
	Generation           uint64
	PID                  int
	DiagnosticBytes      int
	DiagnosticsTruncated bool
}

// MemberSpec binds one fixed service name to its private launch specification.
// It is accepted only when constructing an internal Set, never from HTTP/RPC.
type MemberSpec struct {
	Name    string
	Process Spec
}

type MemberSnapshot struct {
	Name    string
	Process Snapshot
}

// SetSnapshot is an internal aggregate observation. Member order is the fixed
// start order; stop and rollback use its reverse.
type SetSnapshot struct {
	State      State
	Generation uint64
	Members    []MemberSnapshot
}

func (Snapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("managed process state is internal and not serializable")
}

func (*Snapshot) UnmarshalJSON([]byte) error {
	return errors.New("managed process state cannot be deserialized")
}

func (SetSnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("managed process set state is internal and not serializable")
}

func (*SetSnapshot) UnmarshalJSON([]byte) error {
	return errors.New("managed process set state cannot be deserialized")
}

// Owner serializes lifecycle transitions for one process. It intentionally
// provides no process discovery/adoption or automatic restart path.
type Owner struct {
	gate            chan struct{}
	state           State
	generation      uint64
	current         *managedProcess
	reviewRequired  bool
	diagnosticsMu   sync.RWMutex
	lastDiagnostics *diagnosticRing
}

func New() *Owner {
	return &Owner{gate: make(chan struct{}, 1), state: StateStopped}
}

// Diagnostics returns a copy of the bounded private stdout/stderr tail for a
// trusted local caller. It may contain paths or account names. Never serialize,
// log, or return it from a network handler without a separate redaction pass.
func (o *Owner) Diagnostics() []byte {
	if o == nil {
		return nil
	}
	o.diagnosticsMu.RLock()
	ring := o.lastDiagnostics
	o.diagnosticsMu.RUnlock()
	if ring == nil {
		return nil
	}
	return ring.snapshot()
}

func snapshot(state State, generation uint64, pid int, diagnostics *diagnosticRing) Snapshot {
	count, truncated := 0, false
	if diagnostics != nil {
		count, truncated = diagnostics.status()
	}
	return Snapshot{State: state, Generation: generation, PID: pid,
		DiagnosticBytes: count, DiagnosticsTruncated: truncated}
}

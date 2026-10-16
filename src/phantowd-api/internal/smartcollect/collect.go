// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smartcollect coordinates a trusted backend's single SMART capture.
// It supplies no device, process, ioctl, persistent state or network authority.
package smartcollect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartreport"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

const MaxStderr = 4096

var (
	ErrInvalid    = errors.New("invalid fixed SMART collection inputs")
	ErrBusy       = errors.New("SMART collection busy")
	ErrClosed     = errors.New("SMART collection closed")
	ErrReview     = errors.New("SMART collection requires review")
	ErrSource     = errors.New("SMART source observation refused")
	ErrUnsettled  = errors.New("SMART process ownership unsettled")
	ErrCollection = errors.New("SMART collection result refused")
	ErrReport     = errors.New("SMART report refused")
	ErrPrivate    = errors.New("SMART collection evidence is internal")
)

// Target is trusted transient discovery input, not a persistent media identity
// or a token authorizing a command. No filesystem paths or bay IDs are accepted.
type Target struct {
	Generation  volumeprobe.BlockDeviceGeneration
	CensusToken [32]byte
}

type SourceState uint8

const (
	SourceUnknown SourceState = iota
	SourceAdmitted
	SourceAbsent
	SourceAmbiguous
	SourceIncomplete
	SourceUnsupported
)

type Source struct {
	State  SourceState
	Target Target
}

type Termination uint8

const (
	TerminationUnknown Termination = iota
	Exited
	Signaled
	TimedOut
	Canceled
)

// Result comes from a separately trusted process owner. Exited must mean a real
// ordinary exit, not a signal encoded as 128+signal or a timeout wrapper code.
type Result struct {
	Termination    Termination
	ExitCode       int
	Stdout, Stderr []byte
}

// Backend is fixed at construction. The provider owns descriptor/runtime
// provenance, capture/output bounds and process cleanup. Synthetic test providers
// do not establish device provenance or grant physical command authority.
// Settled must freshly verify no still-owned child, not merely a returned reply.
type Backend interface {
	Observe(context.Context) (Source, error)
	Capture(context.Context) (Result, error)
	Settled(context.Context) (bool, error)
}

type Collector struct {
	self       *Collector
	gate       chan struct{}
	backend    Backend
	target     Target
	timeout    time.Duration
	review     bool
	closed     bool
	compareATA bool
	comparison smartreport.ATAReportComparison
}

type Sample struct {
	report     smartreport.Observation
	generation volumeprobe.BlockDeviceGeneration
	valid      bool
}

func (s Sample) Valid() bool                                   { return s.valid }
func (s Sample) Report() smartreport.Observation               { return s.report }
func (s Sample) Generation() volumeprobe.BlockDeviceGeneration { return s.generation }

// New copies target/budget and retains the trusted backend; no I/O occurs.
func New(backend Backend, target Target, timeout time.Duration) (*Collector, error) {
	return newCollector(backend, target, timeout, smartreport.ATAReportComparison{}, false)
}

// NewWithATAReportComparison adds a fixed expected-report comparison to the
// original collection lifecycle. Used only by synthetic host/ARM fixtures; it
// supplies no source/transport/runtime/wake or physical SMART authority. A
// comparison failure latches review; changing inputs cannot retry that lifetime.
func NewWithATAReportComparison(backend Backend, target Target, timeout time.Duration, comparison smartreport.ATAReportComparison) (*Collector, error) {
	if !comparison.Valid() {
		return nil, ErrInvalid
	}
	return newCollector(backend, target, timeout, comparison, true)
}

func newCollector(backend Backend, target Target, timeout time.Duration, comparison smartreport.ATAReportComparison, compareATA bool) (*Collector, error) {
	if backend == nil || !validTarget(target) || timeout < time.Second || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	v := reflect.ValueOf(backend)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil, ErrInvalid
		}
	}
	c := &Collector{gate: make(chan struct{}, 1), backend: backend, target: target, timeout: timeout, comparison: comparison, compareATA: compareATA}
	c.self = c
	return c, nil
}

func validTarget(target Target) bool {
	g := target.Generation
	return (g.Major != 0 || g.Minor != 0) && g.DiskSequence != 0 && target.CensusToken != [32]byte{}
}

func (c *Collector) enter(ctx context.Context) error {
	if c == nil || c.self != c || c.gate == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

func (c *Collector) source(ctx context.Context) error {
	observed, err := c.backend.Observe(ctx)
	if err != nil || observed.State != SourceAdmitted || observed.Target != c.target {
		c.review = true
		return ErrSource
	}
	return nil
}

func (c *Collector) settled(ctx context.Context) error {
	ok, err := c.backend.Settled(ctx)
	if err != nil || !ok || ctx.Err() != nil {
		c.review = true
		return ErrUnsettled
	}
	return nil
}

// Collect performs exactly one accepted capture; no backend/target is supplied
// by this operation. It never publishes partial evidence or retries a command.
func (c *Collector) Collect(ctx context.Context) (Sample, error) {
	if err := c.enter(ctx); err != nil {
		return Sample{}, err
	}
	defer func() { <-c.gate }()
	if c.closed {
		return Sample{}, ErrClosed
	}
	if c.review {
		return Sample{}, ErrReview
	}
	operation, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.source(operation); err != nil {
		return Sample{}, err
	}
	if err := c.settled(operation); err != nil {
		return Sample{}, err
	}
	if err := operation.Err(); err != nil {
		return Sample{}, err
	}
	result, captureErr := c.backend.Capture(operation)
	// Cancellation does not justify abandoning the backend's owned child.
	verification, finish := context.WithTimeout(context.Background(), time.Second)
	settleErr := c.settled(verification)
	finish()
	if settleErr != nil {
		return Sample{}, settleErr
	}
	if err := operation.Err(); err != nil {
		return Sample{}, err
	}
	if captureErr != nil || result.Termination != Exited || result.ExitCode < 0 || result.ExitCode > 255 ||
		len(result.Stdout) > smartreport.MaxBytes || len(result.Stderr) > MaxStderr {
		return Sample{}, ErrCollection
	}
	var report smartreport.Observation
	var err error
	if c.compareATA {
		report, err = c.comparison.Parse(result.Stdout, result.ExitCode)
	} else {
		report, err = smartreport.Parse(result.Stdout, result.ExitCode)
	}
	if err != nil {
		if c.compareATA {
			c.review = true
		}
		return Sample{}, ErrReport
	}
	if err := c.source(operation); err != nil {
		return Sample{}, err
	}
	if err := operation.Err(); err != nil {
		return Sample{}, err
	}
	return Sample{report: report, generation: c.target.Generation, valid: true}, nil
}

// Close sends no signals and closes no provider descriptor. It refuses active
// capture and retains its backend reference until settled ownership is verified.
// A reviewed instance can close, but cannot collect again or clear review.
func (c *Collector) Close(ctx context.Context) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.closed {
		return nil
	}
	verification, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.settled(verification); err != nil {
		return err
	}
	c.backend = nil
	c.closed = true
	return nil
}

func (Target) MarshalJSON() ([]byte, error)     { return nil, ErrPrivate }
func (*Target) UnmarshalJSON([]byte) error      { return ErrPrivate }
func (Source) MarshalJSON() ([]byte, error)     { return nil, ErrPrivate }
func (*Source) UnmarshalJSON([]byte) error      { return ErrPrivate }
func (Result) MarshalJSON() ([]byte, error)     { return nil, ErrPrivate }
func (*Result) UnmarshalJSON([]byte) error      { return ErrPrivate }
func (Sample) MarshalJSON() ([]byte, error)     { return nil, ErrPrivate }
func (*Sample) UnmarshalJSON([]byte) error      { return ErrPrivate }
func (*Collector) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Collector) UnmarshalJSON([]byte) error   { return ErrPrivate }
func (Collector) Format(s fmt.State, _ rune)    { _, _ = io.WriteString(s, "smart-collector{private}") }

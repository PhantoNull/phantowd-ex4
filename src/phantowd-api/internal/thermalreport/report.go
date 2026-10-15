// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package thermalreport evaluates caller-supplied thermal observations in memory.
// It performs no I/O, temperature conversion, health assessment or control.
// Separate tach arithmetic does not qualify counts, windows or calibration.
// The trusted caller must qualify sources, generations, clocks and ranges.
package thermalreport

import (
	"errors"
	"time"
)

const MaxSources = 8

var (
	ErrInvalid = errors.New("invalid thermal observation inputs")
	ErrPrivate = errors.New("thermal observation is internal")
)

type Kind uint8

const (
	BoardTemperature Kind = iota + 1
	DiskTemperature
	FanTachometer
)

type Unit uint8

const (
	Raw Unit = iota + 1
	MilliCelsius
	RPM
)

// Source describes a caller-declared logical source, not a device authorization.
// Generation is transient; ID is neither a bay nor a persistent hardware ID.
// Qualified and Min/Max are caller assertions, not calibration evidence or safe
// operating limits. Raw input can never produce a current numerical value.
type Source struct {
	ID         string
	Generation uint64
	Kind       Kind
	Unit       Unit
	Qualified  bool
	Min, Max   int64
}

type Status uint8

const (
	Observed Status = iota + 1
	Unavailable
	ReadFailed
	Sleeping
)

// Sample timestamps and now must use the same trusted monotonic origin.
// This package cannot establish that provenance. A non-Observed status carries
// no value; Sleeping is only meaningful for a declared disk source. Neither
// a command request nor an unqualified legacy bitmap is a sleep observation.
type Sample struct {
	ID         string
	Generation uint64
	CapturedAt time.Duration
	Status     Status
	Value      int64
}

// State describes observation usability, never temperature or fan health.
type State uint8

const (
	Missing State = iota
	IdentityMismatch
	InvalidTime
	Stale
	SourceUnavailable
	SourceReadFailed
	SourceSleeping
	Unqualified
	OutOfRange
	Current
)

// Reading and Report are immutable private projections, not HTTP DTOs. A value
// is accessible only while Current in this point-in-time evaluation. Retaining
// a Report does not advance its age; consumers must evaluate again before use.
type Reading struct {
	id     string
	kind   Kind
	unit   Unit
	state  State
	status Status
	value  int64
}

func (r Reading) ID() string     { return r.id }
func (r Reading) Kind() Kind     { return r.kind }
func (r Reading) Unit() Unit     { return r.unit }
func (r Reading) State() State   { return r.state }
func (r Reading) Status() Status { return r.status }
func (r Reading) Value() (int64, bool) {
	if r.state != Current {
		return 0, false
	}
	return r.value, true
}
func (Reading) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Reading) UnmarshalJSON([]byte) error  { return ErrPrivate }

type Report struct{ readings []Reading }

func (r Report) Readings() []Reading { return append([]Reading(nil), r.readings...) }

// AllReportedCurrent refers only to the caller-declared roster at evaluation.
// It is not hardware completeness, safe temperature, a spinning fan, a lease,
// permission to reduce cooling or an authorization to start any workload.
func (r Report) AllReportedCurrent() bool {
	if len(r.readings) == 0 {
		return false
	}
	for _, reading := range r.readings {
		if reading.state != Current {
			return false
		}
	}
	return true
}
func (Report) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Report) UnmarshalJSON([]byte) error  { return ErrPrivate }

// Evaluate builds a complete projection of the expected roster in input order.
// Missing samples remain explicit. Invalid shape/duplicate/unknown sources
// return a zero Report, never partially reassuring output. Freshness is strict:
// age >= maxAge is stale. There are no default TTLs, ranges, thresholds, cached
// last-good values, model-name adjustments or nominal RPM substitutions.
// Inputs must not be mutated concurrently with this call.
func Evaluate(sources []Source, samples []Sample, now, maxAge time.Duration) (Report, error) {
	if len(sources) == 0 || len(sources) > MaxSources || len(samples) > len(sources) || now < 0 || maxAge <= 0 {
		return Report{}, ErrInvalid
	}
	indexes := make(map[string]int, len(sources))
	for i, source := range sources {
		if !validSource(source) {
			return Report{}, ErrInvalid
		}
		if _, exists := indexes[source.ID]; exists {
			return Report{}, ErrInvalid
		}
		indexes[source.ID] = i
	}
	bySource := make(map[string]Sample, len(samples))
	for _, sample := range samples {
		i, known := indexes[sample.ID]
		if !known || sample.Status < Observed || sample.Status > Sleeping ||
			(sample.Status != Observed && sample.Value != 0) ||
			(sample.Status == Sleeping && sources[i].Kind != DiskTemperature) {
			return Report{}, ErrInvalid
		}
		if _, exists := bySource[sample.ID]; exists {
			return Report{}, ErrInvalid
		}
		bySource[sample.ID] = sample
	}
	result := Report{readings: make([]Reading, len(sources))}
	for i, source := range sources {
		reading := Reading{id: source.ID, kind: source.Kind, unit: source.Unit}
		if sample, exists := bySource[source.ID]; exists {
			reading.status = sample.Status
			reading.state = evaluate(source, sample, now, maxAge)
			if reading.state == Current {
				reading.value = sample.Value
			}
		}
		result.readings[i] = reading
	}
	return result, nil
}

func evaluate(source Source, sample Sample, now, maxAge time.Duration) State {
	switch {
	case sample.Generation != source.Generation:
		return IdentityMismatch
	case sample.CapturedAt < 0 || sample.CapturedAt > now:
		return InvalidTime
	case now-sample.CapturedAt >= maxAge:
		return Stale
	case sample.Status == Unavailable:
		return SourceUnavailable
	case sample.Status == ReadFailed:
		return SourceReadFailed
	case sample.Status == Sleeping:
		return SourceSleeping
	case !source.Qualified || source.Unit == Raw:
		return Unqualified
	case sample.Value < source.Min || sample.Value > source.Max:
		return OutOfRange
	default:
		return Current
	}
}

func validSource(source Source) bool {
	if len(source.ID) == 0 || len(source.ID) > 48 || source.Generation == 0 ||
		source.Kind < BoardTemperature || source.Kind > FanTachometer ||
		source.Unit < Raw || source.Unit > RPM || source.Min > source.Max {
		return false
	}
	for i := 0; i < len(source.ID); i++ {
		c := source.ID[i]
		if (c >= 'a' && c <= 'z') || (i > 0 && ((c >= '0' && c <= '9') || c == '.' || c == '-')) {
			continue
		}
		return false
	}
	if source.Unit == Raw {
		return !source.Qualified
	}
	if source.Kind == FanTachometer {
		return source.Unit == RPM && source.Min >= 0
	}
	return source.Unit == MilliCelsius
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package thermalreport

import (
	"errors"
	"math"
	"math/bits"
	"time"
)

var (
	ErrInvalidTach  = errors.New("invalid tachometer calculation inputs")
	ErrTachOverflow = errors.New("tachometer calculation exceeds representable RPM")
)

// TachEstimate retains the caller-supplied count, window and conversion factor.
// It is arithmetic evidence only: it establishes no sensor identity, acquisition
// quality, clock provenance, actual transitions/revolution or physical speed.
type TachEstimate struct {
	transitions   uint64
	window        time.Duration
	perRevolution uint32
	rpm           int64
	fraction      bool
	valid         bool
}

func (e TachEstimate) Valid() bool                      { return e.valid }
func (e TachEstimate) Transitions() uint64              { return e.transitions }
func (e TachEstimate) Window() time.Duration            { return e.window }
func (e TachEstimate) TransitionsPerRevolution() uint32 { return e.perRevolution }

// HasFraction reports whether the exact rational result has a fractional part.
// RPM is always rounded down; no threshold or nominal value is substituted.
func (e TachEstimate) HasFraction() bool          { return e.fraction }
func (e TachEstimate) RPM() (int64, bool)         { return e.rpm, e.valid }
func (TachEstimate) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*TachEstimate) UnmarshalJSON([]byte) error  { return ErrPrivate }

// EstimateTach calculates floor(transitions * 60e9 / (window_ns * perRevolution))
// exactly with bounded integer arithmetic. Both denominator factors must be
// positive. Overflow returns no estimate instead of clipping/wrapping a number.
//
// The future trusted provider must independently qualify counting, elapsed
// monotonic window, calibrated factor, identity and sampling resolution. In
// particular zero (including a positive count rounded below 1 RPM) does not
// establish a stopped fan, and success does not qualify a thermalreport.Source.
// No hardware, clock, per-call heap allocation, I/O, admission or control.
func EstimateTach(transitions uint64, window time.Duration, perRevolution uint32) (TachEstimate, error) {
	if window <= 0 || perRevolution == 0 {
		return TachEstimate{}, ErrInvalidTach
	}
	nhi, nlo := bits.Mul64(transitions, uint64(time.Minute))
	dhi, dlo := bits.Mul64(uint64(window), uint64(perRevolution))
	quotient, fraction, fits := tachQuotient(nhi, nlo, dhi, dlo)
	if !fits || quotient > math.MaxInt64 {
		return TachEstimate{}, ErrTachOverflow
	}
	return TachEstimate{transitions: transitions, window: window, perRevolution: perRevolution,
		rpm: int64(quotient), fraction: fraction, valid: true}, nil
}

// Divide two unsigned 128-bit products without floating point or big.Int.
// A 64-bit denominator permits Div64 after its overflow precondition. Otherwise
// the numerator is at most 100 bits, so at most 36 subtract/shift steps suffice
// (a nonzero high denominator word is at least 65 bits). No data-sized loop.
func tachQuotient(nhi, nlo, dhi, dlo uint64) (uint64, bool, bool) {
	if dhi == 0 {
		if nhi >= dlo {
			return 0, false, false
		}
		q, remainder := bits.Div64(nhi, nlo, dlo)
		return q, remainder != 0, true
	}
	if nhi < dhi || (nhi == dhi && nlo < dlo) {
		return 0, nhi != 0 || nlo != 0, true
	}
	shift := bits.Len64(nhi) - bits.Len64(dhi)
	var quotient uint64
	for i := shift; i >= 0; i-- {
		hi, lo := dhi, dlo
		if i != 0 {
			hi, lo = dhi<<i|dlo>>(64-i), dlo<<i
		}
		if nhi > hi || (nhi == hi && nlo >= lo) {
			var borrow uint64
			nlo, borrow = bits.Sub64(nlo, lo, 0)
			nhi, _ = bits.Sub64(nhi, hi, borrow)
			quotient |= uint64(1) << i
		}
	}
	return quotient, nhi != 0 || nlo != 0, true
}

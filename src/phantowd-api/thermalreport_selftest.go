//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"math"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/thermalreport"
)

// This fixture supplies invented sources, clocks and qualification assertions.
// No EX4 calibration, threshold, sensor, disk, serial port or actuator is used.
func exerciseQEMUThermalReport() error {
	sources := []thermalreport.Source{
		{ID: "fixture-board", Generation: 9, Kind: thermalreport.BoardTemperature, Unit: thermalreport.MilliCelsius, Qualified: true, Min: -1000, Max: 1000},
		{ID: "fixture-fan", Generation: 11, Kind: thermalreport.FanTachometer, Unit: thermalreport.RPM, Qualified: true, Min: 0, Max: 1000},
		{ID: "fixture-disk", Generation: 13, Kind: thermalreport.DiskTemperature, Unit: thermalreport.MilliCelsius, Qualified: true, Min: -1000, Max: 1000},
	}
	samples := []thermalreport.Sample{
		{ID: "fixture-fan", Generation: 11, CapturedAt: 10 * time.Second, Status: thermalreport.Observed, Value: 0},
		{ID: "fixture-disk", Generation: 13, CapturedAt: 10 * time.Second, Status: thermalreport.Observed, Value: -1},
		{ID: "fixture-board", Generation: 9, CapturedAt: 10 * time.Second, Status: thermalreport.Observed, Value: 125},
	}
	r, err := thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || !r.AllReportedCurrent() || len(r.Readings()) != 3 {
		return errors.New("synthetic thermal current projection failed")
	}
	if value, current := r.Readings()[1].Value(); !current || value != 0 {
		return errors.New("synthetic thermal zero measurement lost")
	}
	estimate, err := thermalreport.EstimateTach(1, time.Second, 2)
	rpm, valid := estimate.RPM()
	if err != nil || !valid || rpm != 30 || estimate.Transitions() != 1 || estimate.Window() != time.Second || estimate.TransitionsPerRevolution() != 2 {
		return errors.New("synthetic tach count/window calculation failed")
	}
	samples[0].Value = rpm
	r, err = thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || !r.AllReportedCurrent() {
		return errors.New("synthetic tach projection failed")
	}
	// Arithmetic never establishes physical source/calibration qualification.
	sources[1].Qualified = false
	r, err = thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || r.AllReportedCurrent() || r.Readings()[1].State() != thermalreport.Unqualified {
		return errors.New("synthetic tach arithmetic qualified a source")
	}
	sources[1].Qualified = true
	estimate, err = thermalreport.EstimateTach(uint64(1)<<63, time.Duration(1)<<48, uint32(1)<<16)
	rpm, valid = estimate.RPM()
	if err != nil || !valid || rpm != 30000000000 || estimate.HasFraction() {
		return errors.New("synthetic tach wide-product calculation failed")
	}
	estimate, err = thermalreport.EstimateTach(1, 61*time.Second, 1)
	rpm, valid = estimate.RPM()
	if err != nil || !valid || rpm != 0 || !estimate.HasFraction() || estimate.Transitions() != 1 {
		return errors.New("synthetic tach fractional observation lost")
	}
	for _, window := range []time.Duration{0, -1} {
		if e, err := thermalreport.EstimateTach(1, window, 2); !errors.Is(err, thermalreport.ErrInvalidTach) || e.Valid() {
			return errors.New("synthetic tach invalid window accepted")
		}
	}
	if e, err := thermalreport.EstimateTach(math.MaxUint64, 1, 1); !errors.Is(err, thermalreport.ErrTachOverflow) || e.Valid() {
		return errors.New("synthetic tach overflow accepted")
	}
	for _, tc := range []struct {
		change func(*thermalreport.Source, *thermalreport.Sample)
		want   thermalreport.State
	}{
		{func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Generation++ }, thermalreport.IdentityMismatch},
		{func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = 9 * time.Second }, thermalreport.Stale},
		{func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = 12 * time.Second }, thermalreport.InvalidTime},
		{func(_ *thermalreport.Source, s *thermalreport.Sample) {
			s.Status, s.Value = thermalreport.ReadFailed, 0
		}, thermalreport.SourceReadFailed},
		{func(e *thermalreport.Source, _ *thermalreport.Sample) { e.Unit, e.Qualified = thermalreport.Raw, false }, thermalreport.Unqualified},
		{func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Value = 1001 }, thermalreport.OutOfRange},
	} {
		e, s := sources[0], samples[2]
		tc.change(&e, &s)
		observed, err := thermalreport.Evaluate([]thermalreport.Source{e}, []thermalreport.Sample{s}, 11*time.Second, 2*time.Second)
		if err != nil || observed.AllReportedCurrent() || observed.Readings()[0].State() != tc.want {
			return errors.New("synthetic thermal unusable observation accepted")
		}
		if value, current := observed.Readings()[0].Value(); current || value != 0 {
			return errors.New("synthetic thermal unusable value escaped")
		}
	}
	samples[1].Status, samples[1].Value = thermalreport.Sleeping, 0
	r, err = thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || r.AllReportedCurrent() || r.Readings()[2].State() != thermalreport.SourceSleeping {
		return errors.New("synthetic thermal disk sleep treated as current")
	}
	r, err = thermalreport.Evaluate(sources, nil, 11*time.Second, 2*time.Second)
	if err != nil || r.AllReportedCurrent() || r.Readings()[0].State() != thermalreport.Missing {
		return errors.New("synthetic thermal missing observation reused a value")
	}
	samples[2].CapturedAt = time.Duration(math.MaxInt64 - 1)
	r, err = thermalreport.Evaluate(sources[:1], samples[2:], time.Duration(math.MaxInt64), 2)
	if err != nil || !r.AllReportedCurrent() {
		return errors.New("synthetic thermal age overflow check failed")
	}
	sources = append(sources, sources[0])
	r, err = thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if !errors.Is(err, thermalreport.ErrInvalid) || len(r.Readings()) != 0 || r.AllReportedCurrent() {
		return errors.New("synthetic thermal ambiguous roster partially accepted")
	}
	return nil
}

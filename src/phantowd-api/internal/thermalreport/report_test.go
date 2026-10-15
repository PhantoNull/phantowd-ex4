// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package thermalreport_test

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/thermalreport"
)

// All numbers and generations in these tests are synthetic, not EX4 policy.
func source() thermalreport.Source {
	return thermalreport.Source{ID: "board-main", Generation: 7, Kind: thermalreport.BoardTemperature,
		Unit: thermalreport.MilliCelsius, Qualified: true, Min: -1000, Max: 1000}
}

func sample() thermalreport.Sample {
	return thermalreport.Sample{ID: "board-main", Generation: 7, CapturedAt: 10 * time.Second,
		Status: thermalreport.Observed, Value: 125}
}

func TestCurrentValueIsAnObservationNotHealth(t *testing.T) {
	for _, value := range []int64{-1000, 0, 125, 1000} {
		s := sample()
		s.Value = value
		report, err := thermalreport.Evaluate([]thermalreport.Source{source()}, []thermalreport.Sample{s}, 11*time.Second, 2*time.Second)
		if err != nil || !report.AllReportedCurrent() {
			t.Fatalf("current report: %v, %v", report, err)
		}
		rows := report.Readings()
		if len(rows) != 1 || rows[0].ID() != "board-main" || rows[0].Kind() != thermalreport.BoardTemperature ||
			rows[0].Unit() != thermalreport.MilliCelsius || rows[0].State() != thermalreport.Current || rows[0].Status() != thermalreport.Observed {
			t.Fatalf("wrong projection: %+v", rows)
		}
		if got, valid := rows[0].Value(); !valid || got != value {
			t.Fatalf("value=(%d,%v), want (%d,true)", got, valid, value)
		}
	}
}

func TestNoCurrentValueForUnusableObservations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*thermalreport.Source, *thermalreport.Sample)
		state  thermalreport.State
	}{
		{"zero-generation", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Generation = 0 }, thermalreport.IdentityMismatch},
		{"replaced-source", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Generation++ }, thermalreport.IdentityMismatch},
		{"negative-time", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = -1 }, thermalreport.InvalidTime},
		{"future-time", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = 11*time.Second + 1 }, thermalreport.InvalidTime},
		{"ttl-boundary", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = 9 * time.Second }, thermalreport.Stale},
		{"old", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.CapturedAt = 0 }, thermalreport.Stale},
		{"unavailable", func(_ *thermalreport.Source, s *thermalreport.Sample) {
			s.Status, s.Value = thermalreport.Unavailable, 0
		}, thermalreport.SourceUnavailable},
		{"read-failed", func(_ *thermalreport.Source, s *thermalreport.Sample) {
			s.Status, s.Value = thermalreport.ReadFailed, 0
		}, thermalreport.SourceReadFailed},
		{"sleeping", func(e *thermalreport.Source, s *thermalreport.Sample) {
			e.Kind = thermalreport.DiskTemperature
			s.Status, s.Value = thermalreport.Sleeping, 0
		}, thermalreport.SourceSleeping},
		{"not-qualified", func(e *thermalreport.Source, _ *thermalreport.Sample) { e.Qualified = false }, thermalreport.Unqualified},
		{"raw", func(e *thermalreport.Source, _ *thermalreport.Sample) { e.Qualified, e.Unit = false, thermalreport.Raw }, thermalreport.Unqualified},
		{"below-range", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Value = -1001 }, thermalreport.OutOfRange},
		{"above-range", func(_ *thermalreport.Source, s *thermalreport.Sample) { s.Value = 1001 }, thermalreport.OutOfRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, s := source(), sample()
			tt.change(&e, &s)
			r, err := thermalreport.Evaluate([]thermalreport.Source{e}, []thermalreport.Sample{s}, 11*time.Second, 2*time.Second)
			if err != nil || r.AllReportedCurrent() || len(r.Readings()) != 1 {
				t.Fatalf("unusable report: %v, %v", r, err)
			}
			row := r.Readings()[0]
			if row.State() != tt.state || row.Status() != s.Status {
				t.Fatalf("state/status=%v/%v, want %v/%v", row.State(), row.Status(), tt.state, s.Status)
			}
			if value, valid := row.Value(); valid || value != 0 {
				t.Fatalf("unusable value escaped: %d,%v", value, valid)
			}
		})
	}
}

func TestMonotonicBoundaryWithoutAdditionOverflow(t *testing.T) {
	for _, tc := range []struct {
		now, at, ttl time.Duration
		want         thermalreport.State
	}{
		{0, 0, 1, thermalreport.Current},
		{math.MaxInt64, math.MaxInt64 - 1, 2, thermalreport.Current},
		{math.MaxInt64, math.MaxInt64 - 1, 1, thermalreport.Stale},
		{math.MaxInt64, 0, math.MaxInt64, thermalreport.Stale},
		{math.MaxInt64 - 1, math.MaxInt64, 1, thermalreport.InvalidTime},
	} {
		s := sample()
		s.CapturedAt = tc.at
		r, err := thermalreport.Evaluate([]thermalreport.Source{source()}, []thermalreport.Sample{s}, tc.now, tc.ttl)
		if err != nil || r.Readings()[0].State() != tc.want {
			t.Fatalf("%+v: report=%v, err=%v", tc, r, err)
		}
	}
}

func TestBoundedRosterAndZeroRPMRemainObservations(t *testing.T) {
	sources := make([]thermalreport.Source, thermalreport.MaxSources)
	samples := make([]thermalreport.Sample, thermalreport.MaxSources)
	for i := range sources {
		sources[i] = source()
		sources[i].ID = "fixture-" + strconv.Itoa(i)
		samples[i] = sample()
		samples[i].ID = sources[i].ID
	}
	sources[0].Kind, sources[0].Unit, sources[0].Min = thermalreport.FanTachometer, thermalreport.RPM, 0
	samples[0].Value = 0
	r, err := thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || !r.AllReportedCurrent() || len(r.Readings()) != thermalreport.MaxSources {
		t.Fatalf("full roster truncated/refused: %v, %v", r, err)
	}
	if value, valid := r.Readings()[0].Value(); value != 0 || !valid {
		t.Fatal("zero RPM lost; current does not mean fan healthy")
	}
	// Preserve the failed capture status even when its age is the primary state.
	samples[0].Status = thermalreport.ReadFailed
	r, err = thermalreport.Evaluate(sources, samples, 12*time.Second, 2*time.Second)
	if err != nil || r.Readings()[0].State() != thermalreport.Stale || r.Readings()[0].Status() != thermalreport.ReadFailed {
		t.Fatal("age hid capture status")
	}
}

func TestRosterIsCompleteOrderedAndIndependentOfInputs(t *testing.T) {
	board, disk, fan := source(), source(), source()
	disk.ID, disk.Kind = "disk-a", thermalreport.DiskTemperature
	fan.ID, fan.Kind, fan.Unit, fan.Min = "fan-main", thermalreport.FanTachometer, thermalreport.RPM, 0
	sources := []thermalreport.Source{disk, board, fan}
	s := sample()
	samples := []thermalreport.Sample{s}
	r, err := thermalreport.Evaluate(sources, samples, 11*time.Second, 2*time.Second)
	if err != nil || r.AllReportedCurrent() {
		t.Fatalf("partial report: %v, %v", r, err)
	}
	want := []thermalreport.State{thermalreport.Missing, thermalreport.Current, thermalreport.Missing}
	for i, row := range r.Readings() {
		if row.ID() != sources[i].ID || row.State() != want[i] {
			t.Fatalf("roster changed: %+v", r.Readings())
		}
	}
	before := r.Readings()
	sources[1].ID = "replacement"
	samples[0].Value = 999
	returned := r.Readings()
	returned[0] = thermalreport.Reading{}
	if !reflect.DeepEqual(before, r.Readings()) {
		t.Fatal("projection aliases inputs or returned slice")
	}
	// A later evaluation cannot silently reuse the earlier current value.
	later, err := thermalreport.Evaluate([]thermalreport.Source{board}, nil, 12*time.Second, 2*time.Second)
	if err != nil || later.Readings()[0].State() != thermalreport.Missing || later.AllReportedCurrent() {
		t.Fatalf("missing turned into cached current value: %v, %v", later, err)
	}
	if value, valid := later.Readings()[0].Value(); value != 0 || valid {
		t.Fatal("last-good fallback escaped")
	}
}

func TestInvalidShapeReturnsNoPartialReport(t *testing.T) {
	tests := []struct {
		name   string
		change func(*[]thermalreport.Source, *[]thermalreport.Sample, *time.Duration, *time.Duration)
	}{
		{"empty", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) { *e = nil }},
		{"too-many", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			*e = make([]thermalreport.Source, thermalreport.MaxSources+1)
		}},
		{"duplicate-source", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			*e = append(*e, (*e)[0])
		}},
		{"unknown-sample", func(_ *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) { (*s)[0].ID = "other" }},
		{"duplicate-sample", func(e *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) {
			other := source()
			other.ID = "other"
			*e = append(*e, other)
			*s = append(*s, (*s)[0])
		}},
		{"extra-sample", func(_ *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) {
			*s = append(*s, (*s)[0])
		}},
		{"zero-generation", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Generation = 0
		}},
		{"unknown-kind", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) { (*e)[0].Kind = 99 }},
		{"unknown-unit", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) { (*e)[0].Unit = 99 }},
		{"temperature-as-rpm", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Unit = thermalreport.RPM
		}},
		{"fan-as-temperature", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Kind = thermalreport.FanTachometer
		}},
		{"negative-rpm-range", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Kind, (*e)[0].Unit = thermalreport.FanTachometer, thermalreport.RPM
		}},
		{"qualified-raw", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Unit = thermalreport.Raw
		}},
		{"inverted-range", func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) {
			(*e)[0].Max = (*e)[0].Min - 1
		}},
		{"unknown-status", func(_ *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) { (*s)[0].Status = 0 }},
		{"failed-with-value", func(_ *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) {
			(*s)[0].Status = thermalreport.ReadFailed
		}},
		{"board-sleep", func(_ *[]thermalreport.Source, s *[]thermalreport.Sample, _, _ *time.Duration) {
			(*s)[0].Status, (*s)[0].Value = thermalreport.Sleeping, 0
		}},
		{"negative-now", func(_ *[]thermalreport.Source, _ *[]thermalreport.Sample, n, _ *time.Duration) { *n = -1 }},
		{"zero-ttl", func(_ *[]thermalreport.Source, _ *[]thermalreport.Sample, _, ttl *time.Duration) { *ttl = 0 }},
		{"negative-ttl", func(_ *[]thermalreport.Source, _ *[]thermalreport.Sample, _, ttl *time.Duration) { *ttl = -1 }},
	}
	for _, id := range []string{"", "1board", "../board", "board/main", "Board", "b\x00", "b\u00e9", "board-main-that-is-longer-than-forty-eight-ascii-bytes"} {
		tests = append(tests, struct {
			name   string
			change func(*[]thermalreport.Source, *[]thermalreport.Sample, *time.Duration, *time.Duration)
		}{"invalid-id-" + id, func(e *[]thermalreport.Source, _ *[]thermalreport.Sample, _, _ *time.Duration) { (*e)[0].ID = id }})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, s, n, ttl := []thermalreport.Source{source()}, []thermalreport.Sample{sample()}, 11*time.Second, 2*time.Second
			tc.change(&e, &s, &n, &ttl)
			r, err := thermalreport.Evaluate(e, s, n, ttl)
			if !errors.Is(err, thermalreport.ErrInvalid) || len(r.Readings()) != 0 || r.AllReportedCurrent() {
				t.Fatalf("partial/accepted invalid result: %v, %v", r, err)
			}
		})
	}
}

func TestPrivateSerializationAndZeroValues(t *testing.T) {
	r, err := thermalreport.Evaluate([]thermalreport.Source{source()}, []thermalreport.Sample{sample()}, 11*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	row := r.Readings()[0]
	for _, v := range []any{r, &r, row, &row, thermalreport.Report{}, thermalreport.Reading{}} {
		if _, err := json.Marshal(v); !errors.Is(err, thermalreport.ErrPrivate) {
			t.Fatalf("private observation serialized: %T, %v", v, err)
		}
	}
	for _, v := range []any{&r, &row} {
		if err := json.Unmarshal([]byte(`{}`), v); !errors.Is(err, thermalreport.ErrPrivate) {
			t.Fatalf("private observation replaced: %T, %v", v, err)
		}
	}
	if !(thermalreport.Report{}).AllReportedCurrent() && len((thermalreport.Report{}).Readings()) == 0 {
		if value, valid := (thermalreport.Reading{}).Value(); value == 0 && !valid {
			return
		}
	}
	t.Fatal("zero value is reassuring")
}

func FuzzEvaluate(f *testing.F) {
	f.Add(int64(11*time.Second), int64(10*time.Second), int64(2*time.Second), int64(0), uint64(7), uint8(1), uint8(0))
	f.Add(int64(math.MaxInt64), int64(0), int64(1), int64(math.MinInt64), uint64(0), uint8(2), uint8(3))
	f.Fuzz(func(t *testing.T, now, at, ttl, value int64, generation uint64, status, mode uint8) {
		e, s := source(), sample()
		s.CapturedAt, s.Value, s.Generation, s.Status = time.Duration(at), value, generation, thermalreport.Status(status)
		if mode&1 != 0 {
			e.Qualified = false
		}
		if mode&2 != 0 {
			e.Unit, e.Qualified = thermalreport.Raw, false
		}
		r, err := thermalreport.Evaluate([]thermalreport.Source{e}, []thermalreport.Sample{s}, time.Duration(now), time.Duration(ttl))
		if err != nil {
			if !errors.Is(err, thermalreport.ErrInvalid) || len(r.Readings()) != 0 || r.AllReportedCurrent() {
				t.Fatal("invalid inputs returned usable projection")
			}
			return
		}
		row := r.Readings()[0]
		got, valid := row.Value()
		wantCurrent := generation == e.Generation && at >= 0 && at <= now && now-at < ttl &&
			s.Status == thermalreport.Observed && e.Qualified && e.Unit != thermalreport.Raw && value >= e.Min && value <= e.Max
		if valid != wantCurrent || r.AllReportedCurrent() != wantCurrent || (valid && got != value) || (!valid && got != 0) {
			t.Fatalf("value escaped usability checks: %+v valid=%v", row, valid)
		}
	})
}

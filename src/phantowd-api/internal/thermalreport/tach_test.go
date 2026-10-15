// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package thermalreport_test

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/thermalreport"
)

func TestTachUsesActualWindowAndExplicitFactor(t *testing.T) {
	for _, tc := range []struct {
		count    uint64
		window   time.Duration
		factor   uint32
		rpm      int64
		fraction bool
	}{
		{0, time.Second, 2, 0, false},
		{1, time.Second, 2, 30, false},
		{1, 2 * time.Second, 2, 15, false},
		{1, time.Second, 4, 15, false},
		{60, time.Second / 2, 2, 3600, false},
		{35, 3 * time.Second, 4, 175, false},
		{1, 7 * time.Second, 2, 4, true},
		{1, 61 * time.Second, 1, 0, true},
		{math.MaxInt64, time.Minute, 1, math.MaxInt64, false},
		{math.MaxUint64, 2 * time.Minute, 1, math.MaxInt64, true},
	} {
		e, err := thermalreport.EstimateTach(tc.count, tc.window, tc.factor)
		if err != nil || !e.Valid() || e.Transitions() != tc.count || e.Window() != tc.window ||
			e.TransitionsPerRevolution() != tc.factor || e.HasFraction() != tc.fraction {
			t.Fatalf("%+v: estimate=%+v err=%v", tc, e, err)
		}
		if rpm, valid := e.RPM(); !valid || rpm != tc.rpm {
			t.Fatalf("%+v: RPM=%d valid=%v", tc, rpm, valid)
		}
	}
}

func TestTachRejectsInvalidAndUnrepresentableWithoutEstimate(t *testing.T) {
	for _, tc := range []struct {
		count  uint64
		window time.Duration
		factor uint32
		want   error
	}{
		{0, 0, 0, thermalreport.ErrInvalidTach},
		{1, -1, 2, thermalreport.ErrInvalidTach},
		{1, time.Second, 0, thermalreport.ErrInvalidTach},
		{math.MaxUint64, 1, 1, thermalreport.ErrTachOverflow},
		{math.MaxUint64, time.Minute, 1, thermalreport.ErrTachOverflow},
		{math.MaxInt64 + 1, time.Minute, 1, thermalreport.ErrTachOverflow},
	} {
		e, err := thermalreport.EstimateTach(tc.count, tc.window, tc.factor)
		if !errors.Is(err, tc.want) || e != (thermalreport.TachEstimate{}) {
			t.Fatalf("%+v: partial/accepted estimate=%+v, err=%v", tc, e, err)
		}
		if rpm, valid := e.RPM(); valid || rpm != 0 {
			t.Fatal("invalid/overflow exposed a number")
		}
	}
}

func checkTachOracle(t testing.TB, count uint64, window time.Duration, factor uint32) {
	t.Helper()
	e, err := thermalreport.EstimateTach(count, window, factor)
	if window <= 0 || factor == 0 {
		if !errors.Is(err, thermalreport.ErrInvalidTach) || e.Valid() {
			t.Fatal("invalid denominator accepted")
		}
		return
	}
	numerator := new(big.Int).Mul(new(big.Int).SetUint64(count), big.NewInt(int64(time.Minute)))
	denominator := new(big.Int).Mul(big.NewInt(int64(window)), new(big.Int).SetUint64(uint64(factor)))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if !quotient.IsInt64() {
		if !errors.Is(err, thermalreport.ErrTachOverflow) || e != (thermalreport.TachEstimate{}) {
			t.Fatal("unrepresentable result not refused")
		}
		return
	}
	rpm, valid := e.RPM()
	if err != nil || !valid || rpm != quotient.Int64() || e.HasFraction() != (remainder.Sign() != 0) ||
		e.Transitions() != count || e.Window() != window || e.TransitionsPerRevolution() != factor {
		t.Fatalf("count=%d window=%d factor=%d: %v/%v, want %v remainder=%v", count, window, factor, e, err, quotient, remainder)
	}
}

func TestTachExtremeProductsMatchIndependentBigIntegerOracle(t *testing.T) {
	// Products may exceed 64 bits even when the final quotient is small.
	for _, count := range []uint64{0, 1, 2, 3, 100, 1 << 31, 1 << 32, 1 << 63, math.MaxUint64} {
		for _, window := range []time.Duration{1, 3, time.Second / 3, time.Minute, 1 << 32, 1 << 48, math.MaxInt64} {
			for _, factor := range []uint32{1, 2, 3, 1 << 16, 1 << 31, math.MaxUint32} {
				checkTachOracle(t, count, window, factor)
			}
		}
	}
}

func TestTachEvidencePrivateAndZeroValueNotValid(t *testing.T) {
	e, err := thermalreport.EstimateTach(1, time.Second, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{e, &e, thermalreport.TachEstimate{}} {
		if _, err := json.Marshal(value); !errors.Is(err, thermalreport.ErrPrivate) {
			t.Fatalf("evidence serialized: %v", err)
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &e); !errors.Is(err, thermalreport.ErrPrivate) {
		t.Fatalf("evidence replaced: %v", err)
	}
	if e.Valid() != true {
		t.Fatal("refusal changed evidence")
	}
	if rpm, valid := (thermalreport.TachEstimate{}).RPM(); valid || rpm != 0 {
		t.Fatal("zero value looks like a measurement")
	}
}

func FuzzTachEstimate(f *testing.F) {
	f.Add(uint64(60), int64(time.Second), uint32(2))
	f.Add(uint64(math.MaxUint64), int64(math.MaxInt64), uint32(math.MaxUint32))
	f.Add(uint64(math.MaxUint64), int64(1), uint32(1))
	f.Fuzz(func(t *testing.T, count uint64, window int64, factor uint32) {
		checkTachOracle(t, count, time.Duration(window), factor)
	})
}

var tachBenchmarkSink thermalreport.TachEstimate

func BenchmarkTachEstimate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var err error
		tachBenchmarkSink, err = thermalreport.EstimateTach(math.MaxUint64, time.Duration(math.MaxInt64), math.MaxUint32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

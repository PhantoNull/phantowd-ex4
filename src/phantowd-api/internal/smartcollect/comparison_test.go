// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartcollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartreport"
)

const comparedSerial = "SYNTHETIC-ONLY"
const comparedWWN uint64 = 0x5abcdef123456789

func comparisonFixture(t *testing.T) smartreport.ATAReportComparison {
	t.Helper()
	p, err := smartreport.NewATAReportComparison(comparedSerial, comparedWWN)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func comparedReport(exit int) []byte {
	data := strings.Replace(string(reportFixture(exit, exit&8 == 0)), "private-fixture-only", comparedSerial, 1)
	return []byte(strings.TrimSuffix(data, "}") + `,"wwn":{"naa":5,"oui":11259375,"id":4886718345}}`)
}

func TestComparedConstructorAndPrivateLifetime(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	if c, err := NewWithATAReportComparison(b, b.target, time.Second, smartreport.ATAReportComparison{}); c != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("zero comparison accepted")
	}
	p := comparisonFixture(t)
	var typedNil *fakeBackend
	for _, backend := range []Backend{nil, typedNil} {
		if c, err := NewWithATAReportComparison(backend, b.target, time.Second, p); c != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid backend accepted")
		}
	}
	for _, timeout := range []time.Duration{0, time.Second - 1, 30*time.Second + 1} {
		if c, err := NewWithATAReportComparison(b, b.target, timeout, p); c != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid budget accepted")
		}
	}
	if c, err := NewWithATAReportComparison(b, Target{}, time.Second, p); c != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid target accepted")
	}
	c, err := NewWithATAReportComparison(b, b.target, time.Second, p)
	if err != nil || b.observeCalls+b.captureCalls+b.settledCalls != 0 {
		t.Fatal("constructor effects", err)
	}
	p = smartreport.ATAReportComparison{}
	if !c.comparison.Valid() || p.Valid() {
		t.Fatal("comparison not retained by value")
	}
	for _, value := range []any{c, *c} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(verb, value); got != "smart-collector{private}" {
				t.Fatal("collector formatting disclosed private state")
			}
		}
	}
	if data, err := json.Marshal(c); len(data) != 0 || !errors.Is(err, ErrPrivate) {
		t.Fatal("collector serialized")
	}
	copy := *c
	sample, err := copy.Collect(context.Background())
	assertNoSample(t, sample, err, ErrInvalid)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestComparedCollectionPreservesEveryExitProjection(t *testing.T) {
	for exit := 0; exit < 256; exit++ {
		data := comparedReport(exit)
		want, err := smartreport.Parse(data, exit)
		if err != nil {
			t.Fatal(err)
		}
		b := &fakeBackend{target: targetFixture(), capture: func(context.Context) (Result, error) {
			return Result{Termination: Exited, ExitCode: exit, Stdout: data}, nil
		}}
		c, err := NewWithATAReportComparison(b, b.target, time.Second, comparisonFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		sample, err := c.Collect(context.Background())
		if err != nil || !sample.Valid() || sample.Report() != want || sample.Generation() != b.target.Generation ||
			b.captureCalls != 1 || b.observeCalls != 2 || b.settledCalls != 2 {
			t.Fatalf("exit=%d lost projection/lifecycle: %v", exit, err)
		}
		clear(data)
		if sample.Report() != want {
			t.Fatal("raw buffer retained")
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestComparedReportRefusalRetainsReviewAfterRestoration(t *testing.T) {
	good := string(comparedReport(0))
	for name, data := range map[string]string{
		"missing-wwn":    string(reportFixture(0, true)),
		"foreign-serial": strings.Replace(good, comparedSerial, "FOREIGN", 1),
		"foreign-wwn":    strings.Replace(good, "4886718345", "4886718346", 1),
		"non-ata":        strings.Replace(good, `"ATA"`, `"SCSI"`, 1),
		"malformed":      good + "{}",
		"unavailable":    `{"json_format_version":[1,0],"smartctl":{"version":[7,5],"pre_release":false,"exit_status":2}}`,
	} {
		t.Run(name, func(t *testing.T) {
			exit := 0
			if name == "unavailable" {
				exit = 2
			}
			b := &fakeBackend{target: targetFixture(), capture: func(context.Context) (Result, error) {
				return Result{Termination: Exited, ExitCode: exit, Stdout: []byte(data)}, nil
			}}
			c, err := NewWithATAReportComparison(b, b.target, time.Second, comparisonFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			sample, err := c.Collect(context.Background())
			assertNoSample(t, sample, err, ErrReport)
			data, exit = good, 0
			calls := b.observeCalls + b.captureCalls + b.settledCalls
			sample, err = c.Collect(context.Background())
			assertNoSample(t, sample, err, ErrReview)
			if calls != b.observeCalls+b.captureCalls+b.settledCalls || b.captureCalls != 1 {
				t.Fatal("review retried backend")
			}
			if err := c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestComparedCollectionKeepsSourceAndCancellationFences(t *testing.T) {
	for _, name := range []string{"source-change", "canceled", "unsettled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := &fakeBackend{target: targetFixture()}
			b.capture = func(context.Context) (Result, error) {
				if name == "canceled" {
					cancel()
				}
				return Result{Termination: Exited, Stdout: comparedReport(0)}, nil
			}
			b.observe = func(context.Context) (Source, error) {
				target := b.target
				if name == "source-change" && b.captureCalls > 0 {
					target.Generation.DiskSequence++
				}
				return Source{State: SourceAdmitted, Target: target}, nil
			}
			b.settled = func(context.Context) (bool, error) {
				return name != "unsettled" || b.captureCalls == 0, nil
			}
			c, err := NewWithATAReportComparison(b, b.target, time.Second, comparisonFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			sample, err := c.Collect(ctx)
			want := map[string]error{"source-change": ErrSource, "canceled": context.Canceled, "unsettled": ErrUnsettled}[name]
			assertNoSample(t, sample, err, want)
			if b.captureCalls != 1 || b.settledCalls != 2 {
				t.Fatal("capture/independent settlement bypassed")
			}
			b.settled = nil
			if err := c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

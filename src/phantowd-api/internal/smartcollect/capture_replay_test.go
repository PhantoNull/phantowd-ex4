//go:build linux && smartcapture

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartcollect

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartreport"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// Test-only adapter: actual pinned generic producer, fake source census. It is
// not compiled into the product and supplies no device/ioctl/SMART authority.
type replayCaptureBackend struct {
	owner              *processowner.CaptureOwner
	target             Target
	observations       int
	captures           int
	changeAfterCapture bool
	exit               int
	kind               processowner.CaptureExitKind
}

func (b *replayCaptureBackend) Observe(ctx context.Context) (Source, error) {
	if err := ctx.Err(); err != nil {
		return Source{}, err
	}
	b.observations++
	target := b.target
	if b.changeAfterCapture && b.captures > 0 {
		target.Generation.DiskSequence++
	}
	return Source{State: SourceAdmitted, Target: target}, nil
}

func (b *replayCaptureBackend) Capture(ctx context.Context) (Result, error) {
	b.captures++
	result, err := b.owner.Capture(ctx)
	if err != nil {
		return Result{}, err
	}
	b.exit, b.kind = result.ExitCode, result.Kind
	if result.Kind == processowner.CaptureSignaled {
		return Result{Termination: Signaled, ExitCode: -1}, nil
	}
	if result.Kind != processowner.CaptureExited {
		return Result{}, ErrCollection
	}
	return Result{Termination: Exited, ExitCode: result.ExitCode, Stdout: result.Stdout, Stderr: result.Stderr}, nil
}

func (b *replayCaptureBackend) Settled(ctx context.Context) (bool, error) {
	return b.owner.Settled(ctx)
}

func fixedReplayCollector(t *testing.T, name string) (*Collector, *replayCaptureBackend) {
	t.Helper()
	if os.Getenv("PHANTOWD_SMART_CAPTURE_FIXTURE") != "generic-only" || os.Getuid() != 0 {
		t.Fatal("explicit disposable generic-only root fixture required")
	}
	const codePath = "/usr/sbin/phantowd-smartctl-replay"
	inputPath := "/usr/share/phantowd-smart-replay/" + name + ".trace"
	code, err := os.Open(codePath)
	if err != nil {
		t.Fatal("cannot open fixed generic producer")
	}
	defer code.Close()
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal("cannot open fixed synthetic trace")
	}
	defer input.Close()
	owner, err := processowner.NewCapture(processowner.CaptureSpec{
		ExecutableLabel: codePath, Args: []string{"-j", "-i", "-H", "-"},
		RunAs:   &processowner.Credentials{UID: 1000, GID: 1000},
		Timeout: 3 * time.Second, StopTimeout: 100 * time.Millisecond,
	}, code, input)
	if err != nil {
		t.Fatal("cannot retain fixed replay inputs", err)
	}
	target := Target{Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 7}, CensusToken: [32]byte{1}}
	backend := &replayCaptureBackend{owner: owner, target: target}
	collector, err := New(backend, target, 5*time.Second)
	if err != nil {
		_ = owner.Close(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := collector.Close(context.Background()); err != nil {
			t.Error("collector ownership not settled", err)
			return // Retain pins rather than releasing an uncertain process.
		}
		if err := owner.Close(context.Background()); err != nil {
			t.Error("capture pins not safely released", err)
		}
	})
	// The caller descriptors close on return. Capture must use independent pins.
	return collector, backend
}

func TestFixedProducerCapture(t *testing.T) {
	cases := []struct {
		name       string
		exit       int
		state      smartreport.State
		assessment smartreport.Assessment
	}{
		{"pass", 0, smartreport.Complete, smartreport.ReportedPass},
		{"fail", 8, smartreport.Complete, smartreport.ReportedFail},
		{"partial-fail", 12, smartreport.Partial, smartreport.ReportedFail},
		{"partial-pass", 4, smartreport.Partial, smartreport.ReportedPass},
		{"unsupported", 4, smartreport.UnsupportedSMART, smartreport.NoAssessment},
		{"disabled", 0, smartreport.Disabled, smartreport.NoAssessment},
		{"empty", 2, smartreport.Unavailable, smartreport.NoAssessment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector, backend := fixedReplayCollector(t, tc.name)
			sample, err := collector.Collect(context.Background())
			if err != nil || !sample.Valid() || sample.Generation() != backend.target.Generation ||
				backend.kind != processowner.CaptureExited || backend.exit != tc.exit ||
				backend.captures != 1 || backend.observations != 2 {
				t.Fatal("ordinary capture or synthetic source binding failed", err)
			}
			report := sample.Report()
			if report.State() != tc.state || report.Assessment() != tc.assessment ||
				report.Flags().SMARTCommandError != (tc.exit&4 != 0) || report.Flags().FailingStatus != (tc.exit&8 != 0) {
				t.Fatal("reported failure/partial/unsupported/disabled distinction lost")
			}
			if settled, err := backend.Settled(context.Background()); !settled || err != nil {
				t.Fatal("capture returned with unsettled child", err)
			}
			repeated, err := collector.Collect(context.Background())
			if repeated.Valid() || !errors.Is(err, ErrCollection) {
				t.Fatal("consumed producer replay was retried", err)
			}
		})
	}
	// A genuine producer report must still be discarded after source replacement.
	t.Run("source-change", func(t *testing.T) {
		collector, backend := fixedReplayCollector(t, "pass")
		backend.changeAfterCapture = true
		sample, err := collector.Collect(context.Background())
		if sample.Valid() || !errors.Is(err, ErrSource) || backend.captures != 1 || backend.exit != 0 {
			t.Fatal("genuine report survived changed synthetic source", err)
		}
		backend.changeAfterCapture = false
		sample, err = collector.Collect(context.Background())
		if sample.Valid() || !errors.Is(err, ErrReview) || backend.captures != 1 {
			t.Fatal("restoration cleared review or repeated producer", err)
		}
	})
}

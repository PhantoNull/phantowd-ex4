//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"fmt"
	"regexp"
	"testing"
	"time"
)

func TestNativePhaseTimingIsBoundedFixedLabelNonqualifyingTelemetry(t *testing.T) {
	labels := []string{
		"entered", "admitted", "enrolled", "backend-observed",
		"daemon-authenticated", "idle-verified", "clients-prepared",
		"live-verified", "authority-closed", "data-verified",
		"candidate-verified", "startup-verified", "fault-verified",
	}
	grammar := regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_PHASE phase=[a-z-]+ elapsed_ms=[0-9]{1,6} qualifying=false scope=qemu-only$`)
	for phase, label := range labels {
		for _, elapsed := range []time.Duration{0, 999 * time.Microsecond, 123456789 * time.Nanosecond, 10 * time.Minute} {
			row := nativePhaseTimingQEMU(nativeFixturePhaseQEMU(phase), elapsed)
			want := fmt.Sprintf("PHANTOWD_DIAG_NATIVE_PHASE phase=%s elapsed_ms=%d qualifying=false scope=qemu-only", label, elapsed.Milliseconds())
			if row != want || !grammar.MatchString(row) {
				t.Fatalf("phase %d duration %v: %q", phase, elapsed, row)
			}
		}
	}
	for _, phase := range []nativeFixturePhaseQEMU{nativeFixtureFaultVerifiedQEMU + 1, 255} {
		if row := nativePhaseTimingQEMU(phase, time.Second); row != "" {
			t.Fatalf("invalid phase emits telemetry: %q", row)
		}
	}
	for _, elapsed := range []time.Duration{-1, 10*time.Minute + 1, time.Duration(1<<63 - 1)} {
		if row := nativePhaseTimingQEMU(nativeFixtureEnteredQEMU, elapsed); row != "" {
			t.Fatalf("invalid duration emits telemetry: %q", row)
		}
	}
}

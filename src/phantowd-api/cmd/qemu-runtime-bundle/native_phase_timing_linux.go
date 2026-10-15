//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"fmt"
	"time"
)

type nativeFixturePhaseQEMU uint8

const (
	nativeFixtureEnteredQEMU nativeFixturePhaseQEMU = iota
	nativeFixtureAdmittedQEMU
	nativeFixtureEnrolledQEMU
	nativeFixtureBackendObservedQEMU
	nativeFixtureDaemonAuthenticatedQEMU
	nativeFixtureIdleVerifiedQEMU
	nativeFixtureClientsPreparedQEMU
	nativeFixtureLiveVerifiedQEMU
	nativeFixtureAuthorityClosedQEMU
	nativeFixtureDataVerifiedQEMU
	nativeFixtureCandidateVerifiedQEMU
	nativeFixtureStartupVerifiedQEMU
	nativeFixtureFaultVerifiedQEMU
)

// Timing is fixture-only telemetry, not a readiness marker or permission.
// Only fixed phase labels and a bounded cumulative monotonic duration leave
// the guest. No account, path, command output, secret or error text is accepted.
// All campaign acceptance, command/phase/guest deadlines and late fences are
// independent of this observation. In particular a last phase cannot prove
// successful completion or locate a specific worker inside the next phase.
func nativePhaseTimingQEMU(phase nativeFixturePhaseQEMU, elapsed time.Duration) string {
	labels := [...]string{
		"entered", "admitted", "enrolled", "backend-observed",
		"daemon-authenticated", "idle-verified", "clients-prepared",
		"live-verified", "authority-closed", "data-verified",
		"candidate-verified", "startup-verified", "fault-verified",
	}
	if int(phase) >= len(labels) || elapsed < 0 || elapsed > 10*time.Minute {
		return ""
	}
	return fmt.Sprintf("PHANTOWD_DIAG_NATIVE_PHASE phase=%s elapsed_ms=%d qualifying=false scope=qemu-only", labels[phase], elapsed.Milliseconds())
}

func reportNativePhaseTimingQEMU(phase nativeFixturePhaseQEMU, started time.Time) {
	if row := nativePhaseTimingQEMU(phase, time.Since(started)); row != "" {
		fmt.Println(row)
	}
}

type nativeDataPhaseQEMU uint8

const (
	nativeDataEnteredQEMU nativeDataPhaseQEMU = iota
	nativeDataPreparedQEMU
	nativeDataProbedQEMU
	nativeDataClosedQEMU
)

// Local elapsed time starts at this separate data profile, not guest boot or
// credential admission. Rows neither renew a deadline nor qualify completion.
func nativeDataTimingQEMU(phase nativeDataPhaseQEMU, elapsed time.Duration) string {
	labels := [...]string{"entered", "prepared", "probed", "closed"}
	if int(phase) >= len(labels) || elapsed < 0 || elapsed > 10*time.Minute {
		return ""
	}
	return fmt.Sprintf("PHANTOWD_DIAG_NATIVE_DATA phase=%s elapsed_ms=%d qualifying=false scope=qemu-only", labels[phase], elapsed.Milliseconds())
}

func reportNativeDataTimingQEMU(phase nativeDataPhaseQEMU, started time.Time) {
	if row := nativeDataTimingQEMU(phase, time.Since(started)); row != "" {
		fmt.Println(row)
	}
}

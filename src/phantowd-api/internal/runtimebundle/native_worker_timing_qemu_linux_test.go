//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Exercise the real emitter inside a child and the parent's exact-proof output
// boundary. No Samba command, root authority or actual device is involved.
func TestNativeWorkerTimingDefaultLeavesExactProofOutputUntouched(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	if os.Getenv("PHANTOWD_TEST_NATIVE_TIMING_PROOF") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		reportNativeWorkerTimingQEMU(ctx, processowner.NativeSambaCheckQEMU, nativeWorkerAdmissionQEMU, time.Now(), nil)
		fmt.Fprint(os.Stdout, proof)
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWorkerTimingDefaultLeavesExactProofOutputUntouched$", "-test.v=false")
	child.Env = append(os.Environ(), "PHANTOWD_TEST_NATIVE_TIMING_PROOF=1")
	output, err := child.CombinedOutput()
	if err != nil || string(output) != proof {
		t.Fatalf("default timing contaminated exact child proof: %q (%v)", output, err)
	}
}

func TestNativeWorkerTimingAnnotationPreservesContext(t *testing.T) {
	type callerKey struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), callerKey{}, "original"), time.Second)
	defer cancel()
	annotated := WithNativeWorkerTimingQEMU(parent)
	want, bounded := parent.Deadline()
	got, stillBounded := annotated.Deadline()
	if !bounded || !stillBounded || !got.Equal(want) || annotated.Value(callerKey{}) != "original" || annotated.Err() != nil {
		t.Fatal("timing annotation changed context semantics")
	}
	if context.Background().Value(nativeWorkerTimingContextKeyQEMU{}) != nil ||
		annotated.Value(nativeWorkerTimingContextKeyQEMU{}) != true || WithNativeWorkerTimingQEMU(nil) != nil {
		t.Fatal("diagnostic opt-in escaped its context")
	}
	cancel()
	if !errors.Is(annotated.Err(), context.Canceled) || annotated.Done() != parent.Done() {
		t.Fatal("timing annotation detached cancellation")
	}
}

func TestNativeWorkerTimingOptInRemainsDiagnosticOnly(t *testing.T) {
	const proof = "exact-fixed-child-proof\n"
	if os.Getenv("PHANTOWD_TEST_NATIVE_TIMING_OPT_IN") == "1" {
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		reportNativeWorkerTimingQEMU(WithNativeWorkerTimingQEMU(parent), processowner.NativeSambaCheckQEMU, nativeWorkerAdmissionQEMU, time.Now(), nil)
		fmt.Fprint(os.Stdout, proof)
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWorkerTimingOptInRemainsDiagnosticOnly$", "-test.v=false")
	child.Env = append(os.Environ(), "PHANTOWD_TEST_NATIVE_TIMING_OPT_IN=1")
	output, err := child.CombinedOutput()
	grammar := regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_WORKER operation=check phase=pre-admission elapsed_ms=[0-9]{1,6} remaining_ms=[0-9]{1,6} parent_done=false failed=false cause=none qualifying=false scope=qemu-only\nexact-fixed-child-proof\n$`)
	if err != nil || !grammar.Match(output) || string(output) == proof {
		t.Fatalf("opt-in lost telemetry or was accepted as exact proof: %q (%v)", output, err)
	}
}

func TestNativeWorkerTimingOnlyFixedBoundedNonqualifyingFields(t *testing.T) {
	grammar := regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_WORKER operation=(check|list|create|password|enable|disable|status|revoke|sessions) phase=(pre-admission|execution|settlement|post-admission) elapsed_ms=[0-9]{1,6} remaining_ms=[0-9]{1,6} parent_done=(true|false) failed=(true|false) cause=(none|deadline|canceled|mismatch|unavailable|other) qualifying=false scope=qemu-only$`)
	private := errors.New("private-password-path-worker-text\nPHANTOWD_FAKE_READY")
	for operation := processowner.NativeSambaCheckQEMU; operation <= processowner.NativeSambaSessionsQEMU; operation++ {
		for stage := nativeWorkerAdmissionQEMU; stage <= nativeWorkerPostAdmissionQEMU; stage++ {
			for _, test := range []struct {
				err   error
				cause string
			}{
				{nil, "none"}, {private, "other"},
				{errors.Join(private, context.DeadlineExceeded), "deadline"},
				{errors.Join(private, context.Canceled), "canceled"},
				{ErrMismatch, "mismatch"}, {ErrUnavailable, "unavailable"},
			} {
				row := nativeWorkerTimingQEMU(operation, stage, time.Second, 3*time.Second, false, test.err)
				if !grammar.MatchString(row) || !strings.Contains(row, "cause="+test.cause+" ") ||
					strings.Contains(row, "private") || strings.ContainsAny(row, "\r\n") {
					t.Fatalf("invalid or leaking diagnostic: %q", row)
				}
			}
		}
	}
	for _, test := range []struct {
		op                 processowner.NativeSambaOperationQEMU
		stage              nativeWorkerStageQEMU
		elapsed, remaining time.Duration
	}{
		{0, 0, 0, 0}, {255, 0, 0, 0}, {1, nativeWorkerResultQEMU, 0, 0}, {1, 255, 0, 0},
		{1, 0, -1, 0}, {1, 0, 10*time.Minute + 1, 0}, {1, 0, 0, -1}, {1, 0, 0, 10*time.Minute + 1},
	} {
		if row := nativeWorkerTimingQEMU(test.op, test.stage, test.elapsed, test.remaining, false, nil); row != "" {
			t.Fatalf("invalid observation emitted: %q", row)
		}
	}
}

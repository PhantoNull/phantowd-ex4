//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeDataCaptureClockRetainsReturnBeforeCallerCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		time.Sleep(2 * time.Second)
		runtimeClock := startNativeDataClockQEMU(ctx)
		time.Sleep(11 * time.Second)
		captureClock := startNativeDataClockQEMU(ctx)
		time.Sleep(4 * time.Second)
		private := errors.New("private-path/credential\nPHANTOWD_FAKE_READY")
		cause := nativeDataFailureQEMU("escape", nativeWorkerExecutionQEMU, errors.Join(private, context.DeadlineExceeded))
		err := annotateNativeDataCaptureClockQEMU(ctx, captureClock, cause)
		want := NativeDataCaptureClockObservationQEMU{
			NativeDataClockObservationQEMU: NativeDataClockObservationQEMU{
				Present: true, ElapsedMS: 4000, EnteredRemainingMS: 7000, FailedRemainingMS: 3000,
			},
			LimitMS: 4000,
		}
		if got := ObserveNativeDataCaptureClockQEMU(err); got != want {
			t.Fatalf("capture-return observation lost: %+v", got)
		}
		time.Sleep(4 * time.Second) // External settlement crosses the parent deadline.
		synctest.Wait()
		outer := runtimeClock.annotate(ctx, err)
		if got := ObserveNativeDataCaptureClockQEMU(outer); got != want {
			t.Fatalf("cleanup replaced capture-return snapshot: %+v", got)
		}
		parent := ObserveNativeDataClockQEMU(outer)
		if !parent.ContextDone || !parent.DeadlineReached || parent.ElapsedMS != 19000 {
			t.Fatal("outer runtime clock no longer observes its own later boundary", parent)
		}
		if annotateNativeDataCaptureClockQEMU(ctx, captureClock, err) != err ||
			!errors.Is(outer, private) || !errors.Is(outer, context.DeadlineExceeded) ||
			ObserveNativeDataFailureQEMU(outer) != ObserveNativeDataFailureQEMU(cause) ||
			strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatal("capture clock replaced original cause, classification or snapshot")
		}
		copy := ObserveNativeDataCaptureClockQEMU(outer)
		copy.ElapsedMS = 0
		if ObserveNativeDataCaptureClockQEMU(outer) != want {
			t.Fatal("observer exposed mutable clock state")
		}
	})
}

func TestNativeDataCaptureClockActualPreExecRefusalKeepsInputs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this control requires the non-root, no-setuid/setgid-capability host profile")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_1}
	var caps unix.CapUserData
	if err := unix.Capget(&header, &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Effective&((1<<unix.CAP_SETUID)|(1<<unix.CAP_SETGID)) != 0 {
		t.Skip("this control must not have authority to start the fixture's root child")
	}
	// Exercise the actual data-client call site and real Capture admission/close,
	// not a healthy server. Credential change must refuse before /usr/bin/true
	// can execute. No new privilege, daemon or physical resource is involved.
	runtime := nativeReleaseFixture(t)
	helper, err := os.Open("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	runtime.helper = helper
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	before, err := retainedFixtureFDCount()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = runtime.nativeDataClientQEMU(ctx, "escape")
	failure := ObserveNativeDataFailureQEMU(err)
	clock := ObserveNativeDataCaptureClockQEMU(err)
	after, countErr := retainedFixtureFDCount()
	if err == nil || failure.Operation != "escape" || failure.Phase != "execution" ||
		!clock.Present || clock.LimitMS != 4000 || clock.ContextDone || clock.DeadlineReached ||
		runtime.pending != nil || runtime.owner.review || countErr != nil || before != after {
		t.Fatal("real pre-exec refusal lost clock, original inputs or cleanup", failure, clock, err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDataCaptureClockParentClippingAndCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			time.Sleep(18500 * time.Millisecond)
			clock := startNativeDataClockQEMU(ctx)
			time.Sleep(time.Second)
			cause := error(context.Canceled)
			if deadline {
				time.Sleep(501 * time.Millisecond)
				cause = context.DeadlineExceeded
			} else {
				cancel()
			}
			synctest.Wait()
			err := annotateNativeDataCaptureClockQEMU(ctx, clock, nativeDataFailureQEMU("rw-read", nativeWorkerExecutionQEMU, cause))
			got := ObserveNativeDataCaptureClockQEMU(err)
			if !got.Present || got.LimitMS != 4000 || !got.ContextDone || got.DeadlineReached != deadline || got.EnteredRemainingMS != 1500 {
				t.Fatal("parent context state misreported", got)
			}
		})
	}
}

func TestNativeDataCaptureClockDoesNotInventOrDisplaceEvidence(t *testing.T) {
	cause := nativeDataFailureQEMU("escape", nativeWorkerExecutionQEMU, context.DeadlineExceeded)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := startNativeDataClockQEMU(ctx)
	for _, original := range []error{nil, errors.New("private"),
		nativeDataFailureQEMU("escape", nativeWorkerResultQEMU, context.DeadlineExceeded),
		nativeDataFailureQEMU("private", nativeWorkerExecutionQEMU, context.DeadlineExceeded),
		clock.annotate(ctx, cause),
	} {
		if got := annotateNativeDataCaptureClockQEMU(ctx, clock, original); got != original {
			t.Fatal("success, untyped, wrong-stage or already-timed error changed")
		}
	}
	for _, scope := range []context.Context{nil, context.Background()} {
		if got := annotateNativeDataCaptureClockQEMU(scope, startNativeDataClockQEMU(scope), cause); got != cause {
			t.Fatal("missing context invented capture timing")
		}
	}
	err := annotateNativeDataCaptureClockQEMU(ctx, clock, cause)
	first := nativeDataFailureQEMU("ro-read", nativeWorkerExecutionQEMU, context.Canceled)
	if ObserveNativeDataCaptureClockQEMU(errors.Join(first, err)).Present ||
		ObserveNativeDataCaptureClockQEMU((*nativeDataCaptureClockErrorQEMU)(nil)).Present {
		t.Fatal("later or absent capture clock displaced the first failure")
	}
}

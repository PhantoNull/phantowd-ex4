//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestNativeDataClockCapturesOriginalParentBeforeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		time.Sleep(3 * time.Second) // Coordinator work before runtime admission.
		clock := startNativeDataClockQEMU(ctx)
		time.Sleep(17001 * time.Millisecond)
		synctest.Wait()
		private := errors.New("private-credential/path")
		cause := nativeDataFailureQEMU("ungranted", nativeWorkerPostAdmissionQEMU, errors.Join(private, ctx.Err()))
		err := clock.annotate(ctx, cause)
		want := NativeDataClockObservationQEMU{Present: true, ContextDone: true, DeadlineReached: true, ElapsedMS: 17001, EnteredRemainingMS: 17000}
		if got := ObserveNativeDataClockQEMU(err); got != want {
			t.Fatalf("original data deadline lost: %+v", got)
		}
		time.Sleep(9 * time.Second) // Quarantine/cleanup must not change the snapshot.
		if got := ObserveNativeDataClockQEMU(clock.annotate(ctx, err)); got != want {
			t.Fatalf("cleanup replaced first snapshot: %+v", got)
		}
		if !errors.Is(err, private) || !errors.Is(err, context.DeadlineExceeded) ||
			ObserveNativeDataFailureQEMU(err) != ObserveNativeDataFailureQEMU(cause) ||
			strings.Contains(err.Error(), "private") || strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatal("timing changed refusal semantics or disclosed the cause")
		}
		copy := ObserveNativeDataClockQEMU(err)
		copy.ElapsedMS = 0
		if ObserveNativeDataClockQEMU(err) != want {
			t.Fatal("observer exposed mutable snapshot")
		}
	})
}

func TestNativeDataClockDistinguishesWorkerAndParentCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			clock := startNativeDataClockQEMU(ctx)
			time.Sleep(4 * time.Second)
			if canceled {
				cancel()
			}
			cause := nativeDataFailureQEMU("rw-read", nativeWorkerExecutionQEMU, context.DeadlineExceeded)
			got := ObserveNativeDataClockQEMU(clock.annotate(ctx, cause))
			want := NativeDataClockObservationQEMU{Present: true, ContextDone: canceled, ElapsedMS: 4000, EnteredRemainingMS: 20000, FailedRemainingMS: 16000}
			if got != want {
				t.Fatalf("worker deadline misreported as parent expiry: %+v", got)
			}
		})
	}
}

func TestNativeDataClockMissingInvalidAndSuccessfulStayUnchanged(t *testing.T) {
	cause := nativeDataFailureQEMU("rw-read", nativeWorkerExecutionQEMU, context.DeadlineExceeded)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, tc := range []struct {
		ctx   context.Context
		clock nativeDataClockQEMU
	}{
		{nil, startNativeDataClockQEMU(nil)},
		{context.Background(), startNativeDataClockQEMU(context.Background())},
		{ctx, nativeDataClockQEMU{}},
		{ctx, nativeDataClockQEMU{start: time.Now().Add(time.Hour), deadline: time.Now().Add(2 * time.Hour)}},
		{ctx, nativeDataClockQEMU{start: time.Now().Add(-181 * time.Second), deadline: time.Now().Add(time.Second)}},
	} {
		if got := tc.clock.annotate(tc.ctx, cause); got != cause {
			t.Fatal("missing/invalid clock changed original refusal")
		}
	}
	clock := startNativeDataClockQEMU(ctx)
	private := errors.New("private")
	if clock.annotate(ctx, nil) != nil || clock.annotate(ctx, private) != private {
		t.Fatal("success/untyped refusal invented data telemetry")
	}
	for _, err := range []error{nil, private, (*nativeDataClockErrorQEMU)(nil),
		&nativeDataClockErrorQEMU{cause: cause},
		&nativeDataClockErrorQEMU{clock: NativeDataClockObservationQEMU{Present: true}},
		&nativeDataClockErrorQEMU{cause: private, clock: NativeDataClockObservationQEMU{Present: true}},
	} {
		if got := ObserveNativeDataClockQEMU(err); got.Present {
			t.Fatal("unqualified clock observed", got)
		}
	}
}

func TestNativeDataClockBounds(t *testing.T) {
	for _, tc := range []struct {
		clock NativeDataClockObservationQEMU
		valid bool
	}{
		{NativeDataClockObservationQEMU{Present: true}, true},
		{NativeDataClockObservationQEMU{Present: true, ElapsedMS: 180000, EnteredRemainingMS: 180000, DeadlineReached: true}, true},
		{NativeDataClockObservationQEMU{Present: true, ContextDone: true, EnteredRemainingMS: 20, FailedRemainingMS: 10}, true},
		{NativeDataClockObservationQEMU{}, false},
		{NativeDataClockObservationQEMU{Present: true, ElapsedMS: -1}, false},
		{NativeDataClockObservationQEMU{Present: true, ElapsedMS: 180001}, false},
		{NativeDataClockObservationQEMU{Present: true, EnteredRemainingMS: 180001}, false},
		{NativeDataClockObservationQEMU{Present: true, FailedRemainingMS: -1}, false},
		{NativeDataClockObservationQEMU{Present: true, FailedRemainingMS: 1}, false},
		{NativeDataClockObservationQEMU{Present: true, EnteredRemainingMS: 20, ElapsedMS: 19, DeadlineReached: true}, false},
		{NativeDataClockObservationQEMU{Present: true, EnteredRemainingMS: 20, ElapsedMS: 20, FailedRemainingMS: 1, DeadlineReached: true}, false},
	} {
		if got := validNativeDataClockQEMU(tc.clock); got != tc.valid {
			t.Fatalf("unexpected clock admission %+v: %t", tc.clock, got)
		}
	}
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestPendingClientOwnerAbsentCopyBusyCanceledAndClosedRefuse(t *testing.T) {
	client, bootstrap := pendingPlansFixture(t)
	if value, err := newPendingClientOwnerQEMU(context.Background(), client, bootstrap, nil, nil, []byte("fixture-only")); value != nil || err == nil {
		t.Fatal("absent original roots accepted")
	}
	var absent *pendingClientOwnerQEMU
	if absent.start(context.Background()) == nil || absent.closeClient(context.Background()) == nil || absent.stop(context.Background()) == nil || absent.close() == nil {
		t.Fatal("absent owner accepted")
	}
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1)}
	o.self = o
	copied := *o
	if copied.start(context.Background()) == nil || copied.closeClient(context.Background()) == nil || copied.stop(context.Background()) == nil || copied.close() == nil {
		t.Fatal("copied owner accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(o.start(canceled), context.Canceled) || o.started || o.review {
		t.Fatal("pre-admission cancellation mutated lifecycle")
	}
	o.gate <- struct{}{}
	if !errors.Is(o.start(context.Background()), processowner.ErrBusy) || !errors.Is(o.closeClient(context.Background()), processowner.ErrBusy) || !errors.Is(o.stop(context.Background()), processowner.ErrBusy) || !errors.Is(o.close(), processowner.ErrBusy) {
		t.Fatal("exclusive lifecycle gate bypassed")
	}
	<-o.gate
	o.closed = true
	if o.start(context.Background()) == nil || o.closeClient(context.Background()) == nil || o.stop(context.Background()) == nil || o.close() != nil {
		t.Fatal("closed owner readmitted")
	}
}

func TestPendingClientOwnerReviewAndLiveClosureRetainInputs(t *testing.T) {
	// Bookkeeping refusals with a real descriptor, not admitted code/child/SMB.
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	inputs := &pendingClientInputsQEMU{client: &retainedCode{files: map[string]*os.File{"original": file}}}
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1), inputs: inputs, started: true}
	o.self = o
	if !errors.Is(o.close(), processowner.ErrBusy) || o.closed || o.review {
		t.Fatal("live closure released or mutated authority")
	}
	o.review = true
	for index := 0; index < 2; index++ {
		if o.start(context.Background()) == nil || o.closeClient(context.Background()) == nil || o.close() == nil || !o.review || len(inputs.client.files) != 1 {
			t.Fatal("review restarted or released originals")
		}
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("original descriptor released in review")
	}
}

func TestPendingClientOwnerAdapterReleasePrecedesCompleteInputs(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	inputs := &pendingClientInputsQEMU{client: &retainedCode{files: map[string]*os.File{"original": file}}}
	// An invalid concrete adapter's Close refuses: never bypass it with a mock
	// successful process settlement or a replaceable backend.
	o := &pendingClientOwnerQEMU{inputs: inputs, adapter: &processowner.PendingClientQEMU{}}
	if o.release() == nil || o.adapter == nil || len(inputs.client.files) != 1 {
		t.Fatal("unverified adapter release discarded complete originals")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("original descriptor released before adapter")
	}
	witness := errors.New("uncertain close")
	o.releaseErr = witness
	if o.release() != witness || len(inputs.client.files) != 1 {
		t.Fatal("uncertain release retried")
	}
}

func TestPendingClientOwnerStopIsStickyWithoutReadmission(t *testing.T) {
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1), inputs: &pendingClientInputsQEMU{}}
	o.self = o
	if o.stop(nil) == nil || o.review {
		t.Fatal("invalid stop mutated authority")
	}
	for index := 0; index < 2; index++ {
		if !errors.Is(o.stop(context.Background()), ErrReviewRequired) || !o.review || o.closed || o.start(context.Background()) == nil || o.close() == nil {
			t.Fatal("stop/readmission contract changed")
		}
	}
}

func TestPendingClientOwnerInputLossHostRefusesAndPreservesBorrowedRoots(t *testing.T) {
	if sambaCodeFixtureGuard() == nil {
		t.Skip("host refusal only; actual constructor fault has a guarded guest entry")
	}
	client, bootstrap := pendingPlansFixture(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for range 2 {
		if err := client.ProbePendingClientOwnerInputLossQEMU(context.Background(), bootstrap, root, root); !errors.Is(err, ErrInvalid) {
			t.Fatal("host fixture did not refuse before admission", err)
		}
		if _, err := root.Stat(); err != nil {
			t.Fatal("host refusal consumed a caller-owned root", err)
		}
	}
}

func TestPendingClientOwnerReviewPreservesStopAndReleaseCauses(t *testing.T) {
	stopCause, releaseCause := errors.New("stop fixture"), errors.New("release fixture")
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1), review: true, stopTried: true, stopErr: stopCause, releaseErr: releaseCause}
	o.self = o
	for range 2 {
		for _, err := range []error{o.close(), o.start(context.Background()), o.stop(context.Background()), o.recheckCaptureConnectionQEMU(context.Background())} {
			if !errors.Is(err, ErrReviewRequired) || !errors.Is(err, stopCause) || !errors.Is(err, releaseCause) {
				t.Fatal("review lost recorded stop/release uncertainty", err)
			}
		}
	}
}

func TestPendingClientOwnerReviewPreservesFirstCauseAcrossRefusals(t *testing.T) {
	// Diagnostic state only: no admitted input, successful adapter or live child
	// is fabricated. The constructor-backed guest covers the actual input loss.
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1)}
	o.self = o
	first := errors.Join(ErrMismatch, context.DeadlineExceeded)
	if err := o.fail(first); !errors.Is(err, first) {
		t.Fatal("initial failure lost its cause", err)
	}
	replacement := errors.New("later refusal must not replace original")
	if err := o.fail(replacement); !errors.Is(err, first) || errors.Is(err, replacement) {
		t.Fatal("later failure replaced the first cause", err)
	}
	for range 2 {
		_, handleErr := o.initialHandle(context.Background())
		_, frameErr := o.readCaptureFrameQEMU(context.Background())
		for _, err := range []error{o.close(), o.start(context.Background()), o.closeClient(context.Background()), o.stop(context.Background()), o.recheckConnection(context.Background()), o.recheckCaptureConnectionQEMU(context.Background()), handleErr, frameErr} {
			if !errors.Is(err, ErrReviewRequired) || !errors.Is(err, first) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("review refusal lost the first cause", err)
			}
		}
	}
}

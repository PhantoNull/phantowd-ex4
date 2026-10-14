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

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
	"golang.org/x/sys/unix"
)

func TestServerCaptureClientOwnerRefusesMissingInputsAndUnverifiedRelease(t *testing.T) {
	client, bootstrap := pendingPlansFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		value, err := newServerCaptureClientOwnerQEMU(context.Background(), client, bootstrap, nil, nil, []byte("fixture-only"))
		if value != nil || err == nil {
			t.Fatal("absent originals accepted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refusal leaked descriptors", err)
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	inputs := &pendingClientInputsQEMU{client: &retainedCode{files: map[string]*os.File{"original": file}}}
	// Invalid concrete adapter, not a mock of successful process settlement.
	o := &pendingClientOwnerQEMU{inputs: inputs, captureAdapter: &processowner.ServerCaptureClientQEMU{}}
	if o.release() == nil || o.captureAdapter == nil || len(inputs.client.files) != 1 {
		t.Fatal("unverified release discarded originals")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("original released prematurely", err)
	}
	witness := errors.New("uncertain close")
	o.releaseErr = witness
	if o.release() != witness || len(inputs.client.files) != 1 {
		t.Fatal("uncertain release retried")
	}
}

func TestServerCaptureClientOwnerConnectionRejectsMissingCopyCancellationAndBusy(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	var absent *pendingClientOwnerQEMU
	if absent.bindCaptureConnectionQEMU(context.Background(), nil, file, unix.Stat_t{}) == nil || absent.recheckCaptureConnectionQEMU(context.Background()) == nil {
		t.Fatal("absent containing owner admitted")
	}
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1), captureAdapter: &processowner.ServerCaptureClientQEMU{}}
	o.self = o
	copied := *o
	if copied.bindCaptureConnectionQEMU(context.Background(), nil, file, unix.Stat_t{}) == nil || copied.recheckCaptureConnectionQEMU(context.Background()) == nil {
		t.Fatal("copied containing owner admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(o.bindCaptureConnectionQEMU(canceled, nil, file, unix.Stat_t{}), context.Canceled) || o.review || o.capturePeer != nil {
		t.Fatal("canceled containing bind had effects")
	}
	o.gate <- struct{}{}
	if !errors.Is(o.bindCaptureConnectionQEMU(context.Background(), nil, file, unix.Stat_t{}), processowner.ErrBusy) || !errors.Is(o.recheckCaptureConnectionQEMU(context.Background()), processowner.ErrBusy) {
		t.Fatal("containing exclusive gate bypassed")
	}
	<-o.gate
	if o.bindCaptureConnectionQEMU(context.Background(), nil, file, unix.Stat_t{}) == nil || o.capturePeer != nil {
		t.Fatal("unstarted containing bind admitted")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("refusal discarded caller original", err)
	}
}

func TestServerCaptureClientOwnerCopiesCancellationBusyReviewAndDualRolesRefuse(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	// Bookkeeping refusals only; no admitted roots or fabricated healthy child.
	o := &pendingClientOwnerQEMU{gate: make(chan struct{}, 1), captureAdapter: &processowner.ServerCaptureClientQEMU{},
		inputs: &pendingClientInputsQEMU{client: &retainedCode{files: map[string]*os.File{"original": file}}}}
	o.self = o
	copied := *o
	if copied.start(context.Background()) == nil || copied.closeClient(context.Background()) == nil || copied.close() == nil {
		t.Fatal("copied capture owner admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(o.start(canceled), context.Canceled) || o.started || o.review {
		t.Fatal("cancellation had effects")
	}
	o.gate <- struct{}{}
	if !errors.Is(o.start(context.Background()), processowner.ErrBusy) || !errors.Is(o.close(), processowner.ErrBusy) {
		t.Fatal("exclusive gate bypassed")
	}
	<-o.gate
	o.adapter = &processowner.PendingClientQEMU{}
	if o.clientLifecycleQEMU() != nil || o.release() == nil {
		t.Fatal("ambiguous concrete roles admitted/released")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("ambiguous roles released originals")
	}
	o.adapter = nil
	o.review = true
	for range 2 {
		if o.start(context.Background()) == nil || o.closeClient(context.Background()) == nil || o.close() == nil || !o.review {
			t.Fatal("review readmitted or released")
		}
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("review lost original input")
	}
}

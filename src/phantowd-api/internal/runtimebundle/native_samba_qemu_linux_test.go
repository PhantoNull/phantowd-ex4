//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNativeCredentialRuntimeRefusesHostBeforeConsumingRoots(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host admission refusal; ARMv5 fixture qualifies original inputs")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		var plan *Plan
		runtime, err := plan.NewNativeSambaRuntimeQEMU(context.Background(), caller, caller, caller, fileserviceplan.SambaEnrollmentLookup{})
		if runtime != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired credential authority", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("runtime refusal consumed its caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("runtime refusal leaked descriptors", err)
	}
	if docs, err := SambaCredentialDocumentsQEMU(fileserviceplan.SambaEnrollmentLookup{}); docs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("zero native evidence supplied configuration", err)
	}
}

func TestNativeDaemonLifecycleRefusesAbsentCanceledAndBusyAuthority(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	for _, operation := range []func(context.Context) error{
		absent.StartNativeDaemonQEMU, absent.StopNativeDaemonQEMU,
		absent.VerifyNativeIdleDisableQEMU, absent.ProbeNativeDaemonQEMU,
	} {
		if err := operation(context.Background()); !errors.Is(err, ErrInvalid) {
			t.Fatal("absent authority admitted lifecycle", err)
		}
	}
	// No pins or process set: cancellation and exclusive-gate refusal must
	// happen before any file/process access, so these cases need no root fixture.
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, operation := range []func(context.Context) error{
		r.StartNativeDaemonQEMU, r.StopNativeDaemonQEMU, r.VerifyNativeIdleDisableQEMU,
	} {
		if err := operation(canceled); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled lifecycle proceeded", err)
		}
		r.gate <- struct{}{}
		err := operation(context.Background())
		<-r.gate
		if !errors.Is(err, processowner.ErrBusy) {
			t.Fatal("concurrent lifecycle proceeded", err)
		}
	}
}

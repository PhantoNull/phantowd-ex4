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

func TestPlannedConfigurationRetainerRefusesAbsentCanceledBusyAndPrepared(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if err := absent.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaIsolatedCandidate{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime acquired a role", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.RetainPlannedConfigurationQEMU(canceled, nil, fileserviceplan.SambaIsolatedCandidate{}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled role retention admitted", err)
	}
	r.gate <- struct{}{}
	err := r.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaIsolatedCandidate{})
	<-r.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("concurrent role retention admitted", err)
	}
	r.owner.serviceConfiguration = &retainedConfiguration{}
	for _, operation := range []func(context.Context) error{r.StartNativeDaemonQEMU, r.CheckNativeStartupQEMU} {
		if err := operation(context.Background()); !errors.Is(err, ErrReviewRequired) || r.daemonAttempted {
			t.Fatal("inert role admitted a daemon or startup token", err)
		}
	}
	if err := r.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaIsolatedCandidate{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("prepared role was replaceable", err)
	}
}

func TestPlannedConfigurationRetainerRefusesHostWithoutConsumingCaller(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal; actual protected role is qualified only in QEMU")
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
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	for range 16 {
		if err := r.RetainPlannedConfigurationQEMU(context.Background(), caller, plannedDocumentCandidate(t)); !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired a protected daemon role", err)
		}
		if _, err := caller.Stat(); err != nil || r.owner.serviceConfiguration != nil || r.owner.review {
			t.Fatal("host refusal consumed input or changed runtime", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("host refusal leaked descriptors", err)
	}
}

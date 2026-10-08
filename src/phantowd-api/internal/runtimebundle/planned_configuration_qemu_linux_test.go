//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestPlannedManagementMatchesCompleteProtectedExpectation(t *testing.T) {
	plan := plannedDocumentPlan(t)
	roles, err := plan.SambaRoleCandidate()
	if err != nil {
		t.Fatal(err)
	}
	management, service, err := plannedConfigurationPlansQEMU(roles)
	if err != nil || len(management.plan.files) != 7 || len(service.plan.files) != 7 {
		t.Fatal("complete paired expectations missing", err)
	}
	// Test expectation equality only; these contain no authority descriptors.
	actual := func(inputs []File) *retainedConfiguration {
		t.Helper()
		p, err := newConfigurationPlan(inputs)
		if err != nil {
			t.Fatal(err)
		}
		return &retainedConfiguration{contents: &retainedCode{plan: p.plan}}
	}
	if !matchesConfigurationPlanQEMU(actual(management.plan.files), management) ||
		matchesConfigurationPlanQEMU(actual(service.plan.files), management) {
		t.Fatal("management/service expectation separation lost")
	}
	for index := range management.plan.files {
		for _, field := range []string{"digest", "mode", "size", "name"} {
			inputs := slices.Clone(management.plan.files)
			switch field {
			case "digest":
				inputs[index].SHA256[0] ^= 1
			case "mode":
				inputs[index].Mode = 0400
			case "size":
				inputs[index].Size++
			case "name":
				inputs[index].Path += "-other"
			}
			if matchesConfigurationPlanQEMU(actual(inputs), management) {
				t.Fatal("changed management file expectation accepted", index, field)
			}
		}
	}
	if matchesConfigurationPlanQEMU(actual(management.plan.files[:6]), management) ||
		matchesConfigurationPlanQEMU(nil, management) ||
		matchesConfigurationPlanQEMU(&retainedConfiguration{}, management) ||
		matchesConfigurationPlanQEMU(actual(management.plan.files), nil) {
		t.Fatal("incomplete management expectation accepted")
	}
	if m, s, err := plannedConfigurationPlansQEMU(fileserviceplan.SambaRoleCandidate{}); err == nil || m != nil || s != nil {
		t.Fatal("invalid candidate returned partial configuration expectations")
	}
}

func TestPlannedConfigurationRetainerRefusesAbsentCanceledBusyAndPrepared(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if err := absent.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaRoleCandidate{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent runtime acquired a role", err)
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.RetainPlannedConfigurationQEMU(canceled, nil, fileserviceplan.SambaRoleCandidate{}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled role retention admitted", err)
	}
	r.gate <- struct{}{}
	err := r.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaRoleCandidate{})
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
	if err := r.RetainPlannedConfigurationQEMU(context.Background(), nil, fileserviceplan.SambaRoleCandidate{}); !errors.Is(err, ErrReviewRequired) {
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
	plan := plannedDocumentPlan(t)
	roles, err := plan.SambaRoleCandidate()
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		if err := r.RetainPlannedConfigurationQEMU(context.Background(), caller, roles); !errors.Is(err, ErrInvalid) {
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

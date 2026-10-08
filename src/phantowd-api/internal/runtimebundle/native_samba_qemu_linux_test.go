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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
)

// Real empty Owner/lookup and renderer, not a manufactured opaque lookup. All
// writes stay in temporary state; no user operation, daemon or mount is used.
func TestNativeCredentialDocumentsPreserveOwnerFilesOnlyNSS(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-owned temporary identity store; run in isolated root SDK fixture")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"registry", "operations"} {
		if err := os.Mkdir(dir+"/"+name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := serviceaccountstore.Open(dir + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	initErr := store.Initialize(58000, 59000)
	if err := errors.Join(initErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	owner, err := identityowner.Open(dir, func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	lookup, err := fileserviceplan.SambaEnrollmentLookupFromOwner(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil {
		t.Fatal(err)
	}
	documents, err := SambaCredentialDocumentsQEMU(lookup)
	if err != nil || len(documents) != 7 || documents["passwd"] != passwd || documents["group"] != group || documents["nsswitch.conf"] != nss {
		t.Fatal("credential renderer changed Owner-derived lookup", err)
	}
	for _, table := range []string{"passwd", "group", "initgroups", "shadow", "hosts", "networks", "protocols", "services"} {
		if strings.Count(documents["nsswitch.conf"], table+": files\n") != 1 {
			t.Fatal("lookup directive absent or duplicated", table)
		}
	}
	if documents["samba/smb.conf"] != nativeSambaGlobalsQEMU {
		t.Fatal("management renderer changed globals or added share authority")
	}
}

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
		absent.CheckNativeStartupQEMU, absent.StopNativeServiceQEMU,
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
		r.CheckNativeStartupQEMU, r.StopNativeServiceQEMU,
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

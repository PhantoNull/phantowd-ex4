//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNativeDataStopObservationRefusesUnownedAuthority(t *testing.T) {
	var absent *PinnedSet
	if observed, err := absent.ObserveNativeDataStopQEMU(context.Background()); observed != (NativeDataStopObservationQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent process supplied planned-stop evidence", err)
	}
	// Negative-only handles own no process or descriptors. Healthy retention
	// and stop evidence must come from the actual disposable daemon fixture.
	set := &PinnedSet{gate: make(chan struct{}, 1), set: &Set{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := set.ObserveNativeDataStopQEMU(ctx); observed != (NativeDataStopObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled stop observation proceeded", err)
	}
	set.gate <- struct{}{}
	observed, err := set.ObserveNativeDataStopQEMU(context.Background())
	<-set.gate
	if observed != (NativeDataStopObservationQEMU{}) || !errors.Is(err, ErrBusy) {
		t.Fatal("competing stop observation proceeded", err)
	}
	if observed, err := set.ObserveNativeDataStopQEMU(context.Background()); observed != (NativeDataStopObservationQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("unowned process supplied planned-stop evidence", err)
	}
}

func TestNativeDataViewsRefuseAbsentCanceledAndBusyAuthority(t *testing.T) {
	var absent *PinnedSet
	if err := absent.VerifyNativeDataViewsQEMU(context.Background(), 2); !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent process supplied data-view evidence:", err)
	}
	// No executable, descriptor or process exists. Admission must refuse these
	// cases before inspecting any pathname or accepting a caller-selected PID.
	set := &PinnedSet{gate: make(chan struct{}, 1), set: &Set{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := set.VerifyNativeDataViewsQEMU(ctx, 2); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled data-view observation proceeded:", err)
	}
	set.gate <- struct{}{}
	err := set.VerifyNativeDataViewsQEMU(context.Background(), 2)
	<-set.gate
	if !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent data-view observation proceeded:", err)
	}
	for _, pid := range []int{-1, 0, 1, 2} {
		if err := set.VerifyNativeDataViewsQEMU(context.Background(), pid); !errors.Is(err, ErrInvalid) {
			t.Fatal("unowned process supplied data-view evidence:", err)
		}
	}
}

func TestNativeDataDaemonRefusesHostAndPreservesCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal; disposable ARMv5 fixture proves data handoff")
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
	spec := MemberSpec{Name: "native-samba-data", Process: Spec{Executable: "/usr/sbin/phantowd-samba-root-launcher", Args: []string{"native-data-server"}, RunAs: &Credentials{UID: 0, GID: 0}}}
	for range 16 {
		set, err := NewNativeSambaDataPinnedSetQEMU(spec, caller, [5]*os.File{caller, caller, caller, caller, caller}, [7]*os.File{caller, caller, caller, caller, caller, caller, caller}, [2]*os.File{caller, caller})
		if set != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired data daemon authority", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("host refusal consumed caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("data daemon refusal leaked descriptors", err)
	}
}

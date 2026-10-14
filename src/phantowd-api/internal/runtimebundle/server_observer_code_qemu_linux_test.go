//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerObserverCodeRefusesHostWithoutConsumingOrLeakingInputs(t *testing.T) {
	if serverObserverCodeGuardQEMU() == nil {
		t.Skip("host refusal; actual code/path controls run in the dedicated guest")
	}
	plan, err := NewPlan([]File{exampleFile("usr/sbin/smbd")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	caller := os.NewFile(uintptr(fd), "host-observer-refusal-input")
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		retained, err := retainServerObserverCodeQEMU(context.Background(), plan, caller)
		if retained != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired observer code inputs", err)
		}
		if err := plan.ProbeServerObserverCodeBindingQEMU(context.Background(), caller, caller); !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired disposable mount probe", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refusal leaked descriptors", len(before), len(after), err)
	}
	if _, err := caller.Stat(); err != nil {
		t.Fatal("refusal consumed caller", err)
	}
}

func TestServerObserverCodeRefusesCancellationAndMissingInputsBeforeCollection(t *testing.T) {
	plan, err := NewPlan([]File{exampleFile("usr/sbin/smbd")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if retained, err := retainServerObserverCodeQEMU(ctx, plan, caller); retained != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled collection touched inputs", err)
	}
	for _, missing := range []struct {
		ctx  context.Context
		plan *Plan
		root *os.File
	}{{nil, plan, caller}, {context.Background(), nil, caller}, {context.Background(), plan, nil}} {
		if retained, err := retainServerObserverCodeQEMU(missing.ctx, missing.plan, missing.root); retained != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("missing input admitted", err)
		}
	}
	if _, err := caller.Stat(); err != nil {
		t.Fatal("refusal consumed caller", err)
	}
}

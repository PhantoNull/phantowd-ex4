//go:build linux

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

func TestCodePreparationRefusesCanceledBeforeInspectingOrRetainingInputs(t *testing.T) {
	plan, err := NewPlan([]File{exampleFile("bin/fixture")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "caller-root")
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := plan.prepareRetainedCode(ctx, root)
	if code != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation published inputs or inspected the writable root", code, err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("refused preparation consumed the caller's descriptor", err)
	}
}

func TestCodePreparationRefusalsPreserveCallerAndDoNotLeakDescriptors(t *testing.T) {
	plan, err := NewPlan([]File{exampleFile("bin/fixture")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var missing *Plan
	for _, test := range []struct {
		plan *Plan
		ctx  context.Context
	}{{missing, context.Background()}, {plan, nil}, {plan, context.Background()}} {
		if code, err := test.plan.prepareRetainedCode(test.ctx, nil); code != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("missing inputs published prepared code", code, err)
		}
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "caller-writable-root")
	defer root.Close()
	refuse := func() {
		t.Helper()
		if code, err := plan.prepareRetainedCode(context.Background(), root); code != nil || err == nil {
			t.Fatal("unsafe root published code", code, err)
		}
	}
	refuse() // Warm any runtime descriptor before comparing steady-state counts.
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 64 {
		refuse()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refused preparation leaked descriptors", len(before), len(after), err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("refused preparation consumed caller descriptor", err)
	}
	var code *retainedCode
	if !errors.Is(code.revalidate(context.Background()), ErrUnavailable) || code.release() != nil {
		t.Fatal("missing retained code was usable or could not be cleaned up")
	}
}

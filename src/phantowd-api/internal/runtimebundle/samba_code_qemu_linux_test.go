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

func TestSambaCodeLifetimeRefusesMissingInputsBeforeEffects(t *testing.T) {
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
	var missing *Plan
	for _, test := range []struct {
		plan         *Plan
		ctx          context.Context
		root, writer *os.File
	}{{missing, context.Background(), root, root}, {plan, nil, root, root},
		{plan, context.Background(), nil, root}, {plan, context.Background(), root, nil}} {
		if err := test.plan.ProbeSambaCodeLifetimeQEMU(test.ctx, test.root, test.writer); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid fixture inputs were usable", err)
		}
		if _, err := root.Stat(); err != nil {
			t.Fatal("refusal consumed caller", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := plan.ProbeSambaCodeLifetimeQEMU(ctx, root, root); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled fixture admission had effects", err)
	}
	if owner, err := plan.newSambaCodeLifetimeQEMU(ctx, root); owner != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled construction had effects", owner, err)
	}
}

func TestSambaCodeLifetimeRefusesNativeHostWithoutConsumingInputs(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("native refusal only; actual positive lifetime is mandatory in the standalone ARMv5 fixture")
	}
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
	before, err := retainedFixtureFDCount()
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		if err := plan.ProbeSambaCodeLifetimeQEMU(context.Background(), root, root); !errors.Is(err, ErrInvalid) {
			t.Fatal("native host accepted QEMU fixture", err)
		}
		if owner, err := plan.newSambaCodeLifetimeQEMU(context.Background(), root); owner != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("native host constructed privileged fixture", owner, err)
		}
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		t.Fatal("native refusal leaked descriptors", before, after, err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("native refusal consumed caller descriptor", err)
	}
}

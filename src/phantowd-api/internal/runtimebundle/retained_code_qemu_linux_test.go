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

func TestRetainedCodeQEMUProbeRefusesInvalidInputsWithoutConsumingCaller(t *testing.T) {
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
		plan *Plan
		ctx  context.Context
		root *os.File
	}{{missing, context.Background(), root}, {plan, nil, root}, {plan, context.Background(), nil}} {
		observation, err := test.plan.ProbeRetainedCodeQEMU(test.ctx, test.root)
		if !errors.Is(err, ErrInvalid) || observation != (Observation{}) {
			t.Fatal("invalid probe published evidence", observation, err)
		}
		if _, err := root.Stat(); err != nil {
			t.Fatal("probe consumed the caller's descriptor", err)
		}
	}
}

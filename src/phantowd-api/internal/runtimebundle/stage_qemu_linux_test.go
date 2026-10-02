//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
)

func TestStageQEMUInvalidInputsDoNotCreateEntries(t *testing.T) {
	plan, err := NewPlan([]File{{Path: "bin/fixed", SHA256: sha256.Sum256([]byte("fixed")), Size: 5, Mode: 0555}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	name := t.TempDir()
	// An ordinary directory FD is deliberately not an accepted O_PATH root.
	root, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, input := range []struct {
		plan     *Plan
		ctx      context.Context
		src, dst *os.File
	}{
		{nil, context.Background(), root, root},
		{&Plan{}, context.Background(), root, root},
		{plan, nil, root, root},
		{plan, context.Background(), nil, root},
		{plan, context.Background(), root, nil},
		{plan, context.Background(), root, root},
	} {
		if err := input.plan.StageQEMU(input.ctx, input.src, input.dst); !errors.Is(err, ErrInvalid) || errors.Is(err, ErrStageIncomplete) {
			t.Fatalf("invalid roots/inputs: %v", err)
		}
	}
	if entries, err := os.ReadDir(name); err != nil || len(entries) != 0 {
		t.Fatalf("invalid stage changed destination: %v", err)
	}
}

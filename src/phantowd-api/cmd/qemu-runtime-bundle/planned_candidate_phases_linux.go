//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"time"
)

// The two callbacks are fixed fixture workloads, not authority or retry hooks.
// The caller retains the SAME storage roster, share pins and identity/backend.
// Each distinct scenario has its OWN 30-second budget. A failed/expired first
// phase cannot enter the second; cancellation of the parent remains binding.
// This changes only fixture orchestration, not worker or guest/product limits.
func runPlannedCandidatePhasesQEMU(parent context.Context, candidate, prepared func(context.Context) error) error {
	if parent == nil || candidate == nil || prepared == nil {
		return errors.New("planned candidate requires both fixture phases and parent")
	}
	for _, phase := range []func(context.Context) error{candidate, prepared} {
		if err := parent.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		err := phase(ctx)
		contextErr := ctx.Err()
		cancel()
		if err != nil {
			return err
		}
		if contextErr != nil {
			return contextErr
		}
	}
	return nil
}

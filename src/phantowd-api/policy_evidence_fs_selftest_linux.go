//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyepochjournal"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidencefs"
)

func exerciseQEMUPolicyEvidenceFS() error {
	c, err := naspolicy.Decode(strings.NewReader(qemuISCSIPreviewFixture))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := policyepochjournal.ExerciseTemporaryQEMU(ctx, c); err != nil {
		return err
	}
	return policyevidencefs.ExerciseTemporaryQEMU(ctx, c)
}

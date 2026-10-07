//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"testing"
)

func TestQEMUCaptureObservationDistinguishesUnconsumedFromSettled(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/printf", []string{"%s", "synthetic"}, nil)
	ctx := context.Background()
	for range 2 {
		if before, err := c.UnconsumedQEMU(ctx); !before || err != nil {
			t.Fatal("observation consumed or lost unlaunched capture", err)
		}
	}
	if result, err := c.Capture(ctx); err != nil || result.ExitCode != 0 || string(result.Stdout) != "synthetic" {
		t.Fatal("original capture unavailable after observation", err)
	}
	if settled, err := c.Settled(ctx); !settled || err != nil {
		t.Fatal("capture not settled", err)
	}
	if before, err := c.UnconsumedQEMU(ctx); before || err != nil {
		t.Fatal("settled executed capture misreported as unconsumed", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if before, err := c.UnconsumedQEMU(ctx); before || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed capture supplied an observation", err)
	}
}

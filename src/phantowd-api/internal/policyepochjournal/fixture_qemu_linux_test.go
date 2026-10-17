//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"context"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"golang.org/x/sys/unix"
)

func TestTemporaryJournalFixtureOnNativeTmpfs(t *testing.T) {
	var fs unix.Statfs_t
	if unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Skip("the exact fixture requires tmpfs; no positive fixture qualification")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := ExerciseTemporaryQEMU(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

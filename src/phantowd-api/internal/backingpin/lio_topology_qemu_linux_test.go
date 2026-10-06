//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLIOTopologyExactBoundedNames(t *testing.T) {
	expected := []string{"auth", "lun_0", "lun_7"}
	if !lioExactNames(expected, []string{"lun_7", "auth", "lun_0"}) || !lioExactNames(nil, nil) {
		t.Fatal("complete order-independent roster refused")
	}
	for _, bad := range [][]string{{"auth", "lun_0"}, {"auth", "lun_0", "lun_0"}, {"auth", "lun_0", "lun_8"}, {"auth", "lun_0", "lun_7", "foreign"}, {"auth", ".", "lun_7"}, {"auth", "../lun_0", "lun_7"}} {
		if lioExactNames(expected, bad) {
			t.Fatal("partial, duplicate or foreign names accepted")
		}
	}
	for _, bad := range [][]string{{"auth", "auth"}, {""}, {"."}, {".."}, {"a/b"}, {"a\\b"}, {"a\x00b"}, {"a\nb"}, {"a\rb"}, {strings.Repeat("a", 256)}, make([]string, lioRosterLimit+1)} {
		if lioExactNames(bad, bad) {
			t.Fatal("invalid expected roster accepted")
		}
	}
}

func TestLIOTopologyRefusesOrdinaryFilesystemAndCancelledState(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := &lioBackend{prepared: true, started: true, topology: []lioDirectoryRoster{{f, nil}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx, context.Background()} {
		if !errors.Is(b.checkTopology(input), ErrReview) {
			t.Fatal("invalid authority/context admitted")
		}
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("borrowed root consumed on refusal")
	}
}

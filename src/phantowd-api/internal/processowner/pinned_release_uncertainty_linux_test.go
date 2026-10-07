//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPinnedSetCloseDoesNotForgetDescriptorCloseFailure(t *testing.T) {
	original, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	spec := Spec{
		Executable: "/fixed/unused", Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}
	set, err := NewPinnedSet([]MemberSpec{{Name: "first", Process: spec}, {Name: "second", Process: spec}}, []*os.File{original, original})
	if err != nil {
		t.Fatal(err)
	}
	// Fault injection only: no child starts, no raw close/reused-fd race and
	// no user descriptor is touched. A second real Close returns os.ErrClosed.
	if err := set.pins[0].Close(); err != nil {
		t.Fatal(err)
	}
	remaining := set.pins[1]
	t.Cleanup(func() { _ = remaining.Close() })
	first := set.Close()
	if !errors.Is(first, ErrReviewRequired) || !errors.Is(first, os.ErrClosed) {
		t.Error("descriptor close fault did not enter review", first)
	}
	if _, err := remaining.Stat(); err != nil {
		t.Error("uncertain first close released a later executable", err)
	}
	if next := set.Close(); !errors.Is(next, ErrReviewRequired) || !errors.Is(next, os.ErrClosed) {
		t.Error("repeat Close forgot descriptor uncertainty", next)
	}
	if _, err := remaining.Stat(); err != nil {
		t.Error("repeat Close touched a retained executable", err)
	}
	if _, err := set.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Error("failed release allowed another Start", err)
	}
}

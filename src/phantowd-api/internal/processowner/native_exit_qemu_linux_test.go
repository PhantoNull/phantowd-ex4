//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"testing"
)

func TestNativeDataExitRequiresOwnedAuthority(t *testing.T) {
	var absent *PinnedSet
	if attempted, err := absent.RequestNativeDataExitQEMU(context.Background()); attempted || !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent owner attempted a process signal", attempted, err)
	}
}

func TestNativeDataExitRefusesWithoutChangingLifetime(t *testing.T) {
	set := &PinnedSet{gate: make(chan struct{}, 1), set: &Set{}}
	if attempted, err := set.RequestNativeDataExitQEMU(nil); attempted || !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent context attempted a signal", attempted, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if attempted, err := set.RequestNativeDataExitQEMU(ctx); attempted || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request attempted a signal", attempted, err)
	}
	set.gate <- struct{}{}
	attempted, err := set.RequestNativeDataExitQEMU(context.Background())
	<-set.gate
	if attempted || !errors.Is(err, ErrBusy) {
		t.Fatal("competing request attempted a signal", attempted, err)
	}
	for range 2 {
		if attempted, err := set.RequestNativeDataExitQEMU(context.Background()); attempted || !errors.Is(err, ErrInvalid) {
			t.Fatal("host/incomplete fixture attempted a signal", attempted, err)
		}
		if set.closed || set.releaseErr != nil || set.set.reviewRequired || set.set.generation != 0 || len(set.pins) != 0 || len(set.set.members) != 0 || len(set.gate) != 0 {
			t.Fatal("refusal changed unowned lifetime")
		}
	}
	set.closed = true
	if attempted, err := set.RequestNativeDataExitQEMU(context.Background()); attempted || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed lifetime attempted a signal", attempted, err)
	}
}

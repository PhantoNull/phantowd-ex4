//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfsowner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestSourceServerPeerRequiresOriginalExclusiveOwnerAndFixedBackend(t *testing.T) {
	candidate, backend := fixture(t, true)
	owner, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil || owner.Start(context.Background()) != nil {
		t.Fatal("fixture start refused", err)
	}
	copy := *owner
	if !errors.Is(copy.InjectSourceMountdExitFixtureQEMU(context.Background()), nfsowner.ErrInvalid) {
		t.Fatal("copied Owner admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(owner.InjectSourceMountdExitFixtureQEMU(canceled), context.Canceled) {
		t.Fatal("canceled operation admitted")
	}
	if !errors.Is(owner.InjectSourceMountdExitFixtureQEMU(context.Background()), nfsowner.ErrInvalid) {
		t.Fatal("model backend admitted real daemon control")
	}
	if backend.starts != 1 || backend.stops != 0 || backend.releases != 0 || !backend.running {
		t.Fatal("refused control changed lifetime")
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(ctx, time.Hour) }()
	waitSupervisionExclusive(t, owner, done)
	if !errors.Is(owner.InjectSourceMountdExitFixtureQEMU(context.Background()), nfsowner.ErrBusy) {
		stop()
		<-done
		t.Fatal("test mutation bypassed exclusive supervision")
	}
	stop()
	if err := waitSupervisionResult(t, done); !errors.Is(err, context.Canceled) || errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("refused mutation contaminated stop", err)
	}
	if backend.starts != 1 || backend.stops != 1 || backend.releases != 0 || backend.running {
		t.Fatal("unexpected model effects")
	}
}

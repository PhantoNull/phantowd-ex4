//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func TestRetainedOwnerRefusesWritableOrMissingRootBeforeAnyProcess(t *testing.T) {
	plan, err := NewPlan([]File{exampleFile("bin/fixture")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := plan.NewOwner(context.Background(), nil, nil); !errors.Is(err, ErrInvalid) || owner != nil {
		t.Fatal("missing root published an owner", owner, err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "writable-runtime-root")
	defer root.Close()
	specs := []processowner.MemberSpec{{Name: "fixture", Process: processowner.Spec{
		Executable: "/bin/fixture", RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready:        func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}
	if owner, err := plan.NewOwner(context.Background(), root, specs); err == nil || owner != nil {
		t.Fatal("writable root published an owner", owner, err)
	}
}

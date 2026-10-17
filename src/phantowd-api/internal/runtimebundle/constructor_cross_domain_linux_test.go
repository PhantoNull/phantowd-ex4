//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/testclosefault"
	"golang.org/x/sys/unix"
)

// Actual lower public factory plus the actual containing rollback boundary.
// The containing Owner's file references are controlled no-child bookkeeping,
// NOT a successfully admitted bundle, root/namespace/storage grant or service.
func TestConstructorCrossDomainReviewRetainsContainingReferences(t *testing.T) {
	if os.Getenv("PHANTOWD_CROSS_CONSTRUCTION_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConstructorCrossDomainReviewRetainsContainingReferences$")
		command.Env = append(os.Environ(), "PHANTOWD_CROSS_CONSTRUCTION_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cross-domain construction subprocess: %v\n%s", err, output)
		}
		return
	}
	runtime.LockOSThread()
	programPath, err := testclosefault.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.Open(programPath)
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	spec := processowner.Spec{Executable: "/fixed/never-executed", Ready: func(context.Context) (bool, error) {
		t.Fatal("constructor launched a child")
		return false, nil
	}, ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
	warm, err := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "warm", Process: spec}}, []*os.File{program})
	if err != nil || warm.Close() != nil {
		t.Fatal("constructor warmup", err)
	}
	original, later := releaseFaultFile(t, false), releaseFaultFile(t, false)
	owner := &Owner{gate: make(chan struct{}, 1), retainedCode: &retainedCode{root: original},
		sambaState: &retainedSambaState{root: later}}
	owner.self = owner
	target, err := unix.FcntlInt(program.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(target); err != nil { // Raw probe, closed exactly once.
		t.Fatal(err)
	}
	if err := testclosefault.Install(target); err != nil {
		t.Fatal(err)
	}
	set, lower := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "first", Process: spec}, {Name: "invalid", Process: spec}}, []*os.File{program, nil})
	var actual, wanted unix.Stat_t
	if unix.Fstat(target, &actual) != nil || unix.Fstat(int(program.Fd()), &wanted) != nil ||
		actual.Dev != wanted.Dev || actual.Ino != wanted.Ino || set != nil ||
		!errors.Is(lower, unix.EIO) || !errors.Is(lower, processowner.ErrReviewRequired) {
		t.Fatal("lower factory did not retain the actual duplicate close fault", lower)
	}
	result := owner.constructionRollback(fmt.Errorf("trusted process preparation: %w", lower))
	for _, file := range []*os.File{original, later} {
		if _, err := file.Stat(); err != nil {
			t.Fatal("containing constructor released originals after foreign review", err)
		}
	}
	if !owner.review || !errors.Is(result, ErrReviewRequired) || !errors.Is(result, processowner.ErrReviewRequired) ||
		!errors.Is(result, unix.EIO) || !errors.Is(result, processowner.ErrInvalid) {
		t.Fatal("cross-domain review lost classification or original causes", result)
	}
	weakOwner := weak.Make(owner)
	owner = nil
	runtime.GC()
	runtime.GC()
	owner = weakOwner.Value()
	if owner == nil {
		t.Fatal("cross-domain error chain did not retain its containing lifetime")
	}
	for range 2 {
		if err := owner.Close(context.Background()); !errors.Is(err, unix.EIO) || !errors.Is(err, processowner.ErrInvalid) {
			t.Fatal("cross-domain lifetime forgot its causes or retried", err)
		}
		if _, err := original.Stat(); err != nil {
			t.Fatal("cross-domain repeat close released original references", err)
		}
	}
	runtime.KeepAlive(result)
}

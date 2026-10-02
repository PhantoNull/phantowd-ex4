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

func TestPinnedSetSurvivesCallerCloseAndReapsBeforeRelease(t *testing.T) {
	// Root-owned system fixture, not the builder-owned Go test executable.
	file, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	args := []string{"60"}
	set, err := NewPinnedSet([]MemberSpec{{Name: "fixture", Process: Spec{
		Executable: "/fixed/fixture", Args: args,
		Ready:        func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}, []*os.File{file})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = set.Stop(context.Background()); _ = set.Close() })
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	args[0] = "0"
	started, err := set.Start(context.Background())
	if err != nil || started.State != StateReady || started.Members[0].Process.PID <= 1 {
		t.Fatal("independent pinned executable did not start", started, err)
	}
	if err := set.Close(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("live process allowed input release", err)
	}
	stopped, err := set.Stop(context.Background())
	if err != nil || stopped.Members[0].Process.PID != 0 {
		t.Fatal("owned group was not reaped", stopped, err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal("close is not idempotent", err)
	}
	if _, err := set.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("released inputs could restart", err)
	}
}

func TestPinnedSetUncertainStopRetainsPinsUntilExplicitReapVerification(t *testing.T) {
	// The fixed root-owned interpreter runs only this disposable native fixture;
	// this is not runtimebundle's separately constrained static execution adapter.
	file, err := os.Open("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	marker := t.TempDir() + "/ready"
	set, err := NewPinnedSet([]MemberSpec{{Name: "fixture", Process: Spec{
		Executable:   "/fixed/fixture",
		Args:         []string{"-I", "-S", "-c", "import os,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,b'ready'); os.close(fd); time.sleep(60)", marker},
		Ready:        func(context.Context) (bool, error) { _, err := os.Stat(marker); return err == nil, nil },
		ReadyTimeout: 5 * time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: 20 * time.Millisecond,
	}}}, []*os.File{file})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = set.Stop(context.Background()); _ = set.Close() })
	if _, err := set.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	uncertain, err := set.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || uncertain.State != StateReviewRequired || uncertain.Members[0].Process.PID <= 1 {
		t.Fatal("forced cleanup was treated as confirmed graceful cleanup", uncertain, err)
	}
	if err := set.Close(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("uncertain ownership released executable", err)
	}
	if _, err := set.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("uncertain stop allowed restart", err)
	}
	verified, err := set.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || verified.Members[0].Process.PID != 0 {
		t.Fatal("explicit reap verification cleared review or left ownership", verified, err)
	}
	if err := set.Close(); err != nil {
		t.Fatal("confirmed absence still refused input release", err)
	}
}

func TestPinnedSetRejectedConstructionReleasesPartialPins(t *testing.T) {
	file, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	spec := Spec{Executable: "/fixed/fixture", Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
	specs := []MemberSpec{{Name: "first", Process: spec}, {Name: "second", Process: spec}}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, pins := range [][]*os.File{nil, {file}, {file, nil}} {
		if set, err := NewPinnedSet(specs, pins); set != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid or incomplete pins produced an owner", set, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("refused constructor leaked an independent pin", len(before), len(after), err)
	}
}

func TestPinnedSetRefusesBuilderOwnedExecutableWithoutWeakeningRootTrust(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("non-root ownership refusal is exercised by the Buildroot builder")
	}
	name := t.TempDir() + "/untrusted"
	if err := os.WriteFile(name, []byte("not trusted code"), 0555); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	spec := Spec{Executable: "/fixed/fixture", Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
	if owner, err := NewPinnedSet([]MemberSpec{{Name: "fixture", Process: spec}}, []*os.File{file}); owner != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("builder-owned executable was trusted", owner, err)
	}
}

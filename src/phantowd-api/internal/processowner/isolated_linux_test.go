//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func isolationTestSpec() Spec {
	return Spec{Executable: "/fixed/child", Args: []string{"fixed"},
		RunAs:        &Credentials{UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{1002, 1001}},
		Ready:        func(context.Context) (bool, error) { return false, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
}

func TestNewIsolatedRefusesRootWhoseCallerCloseHasBegun(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("constructor requires root; exercised in disposable host/QEMU fixture")
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "closing-isolation-root")
	defer root.Close()
	raw, err := root.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	controlled := make(chan error, 1)
	go func() {
		controlled <- raw.Control(func(uintptr) { close(entered); <-release })
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- root.Close() }()
	defer func() {
		close(release)
		if err := <-controlled; err != nil {
			t.Error("held root control:", err)
		}
		if err := <-closed; err != nil {
			t.Error("caller root close:", err)
		}
	}()
	// A real active Control keeps the kernel FD alive, while Close makes the
	// caller's os.File unavailable. No syscall or fake descriptor is injected.
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := root.Stat(); errors.Is(err, os.ErrClosed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("caller Close did not become observable")
		}
		runtime.Gosched()
	}
	spec := isolationTestSpec()
	spec.Executable = "/usr/bin/sleep"
	owner, err := NewIsolated(spec, Isolation{LauncherExecutable: "/usr/bin/sleep", Root: root})
	if owner != nil {
		_ = owner.Close()
	}
	if owner != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("constructor accepted caller root after Close began:", err)
	}
}

func TestIsolatedSpecIsCopiedAndGroupsAreCanonical(t *testing.T) {
	source := isolationTestSpec()
	fixed, err := isolatedSpec(source)
	if err != nil {
		t.Fatal(err)
	}
	source.Args[0] = "replacement"
	source.RunAs.UID = 0
	source.RunAs.SupplementaryGIDs[0] = 0
	if fixed.Args[0] != "fixed" || fixed.RunAs.UID != 1000 ||
		!reflect.DeepEqual(fixed.RunAs.SupplementaryGIDs, []uint32{1001, 1002}) ||
		isolatedGroups(fixed.RunAs.SupplementaryGIDs) != "1001,1002" || isolatedGroups(nil) != "-" {
		t.Fatal("fixed isolation inputs changed or lost canonical group encoding")
	}
}

func TestIsolatedSpecRefusesUnsafeInputs(t *testing.T) {
	cases := []func(*Spec){
		func(spec *Spec) { spec.RunAs = nil },
		func(spec *Spec) { spec.RunAs.UID = 0 },
		func(spec *Spec) { spec.RunAs.GID = 999 },
		func(spec *Spec) { spec.RunAs.SupplementaryGIDs = []uint32{0} },
		func(spec *Spec) { spec.RunAs.SupplementaryGIDs = []uint32{1000, 1000} },
		func(spec *Spec) { spec.Args = []string{""} },
		func(spec *Spec) { spec.Args = make([]string, 64) },
	}
	for index, change := range cases {
		spec := isolationTestSpec()
		change(&spec)
		if _, err := isolatedSpec(spec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d accepted: %v", index, err)
		}
	}
	if _, err := NewIsolated(isolationTestSpec(), Isolation{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing root accepted:", err)
	}
}

func TestIsolationRejectsSerializationAndNilLifecycle(t *testing.T) {
	if _, err := json.Marshal(Isolation{}); err == nil {
		t.Fatal("isolation construction input serialized")
	}
	var input Isolation
	if err := json.Unmarshal([]byte(`{}`), &input); err == nil {
		t.Fatal("isolation construction input deserialized")
	}
	var owner *IsolatedOwner
	if _, err := owner.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := owner.Stop(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := owner.Observe(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if owner.Diagnostics() != nil || !errors.Is(owner.Close(), ErrUnavailable) {
		t.Fatal("nil isolated owner not unavailable")
	}
	zero := &IsolatedOwner{}
	if _, err := zero.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("zero isolated owner not unavailable:", err)
	}
	if !errors.Is(zero.Close(), ErrUnavailable) {
		t.Fatal("zero isolated owner close not unavailable")
	}
}

func TestBoundLaunchInputLossQuarantinesBeforeAnyChildAndCannotBeRetried(t *testing.T) {
	owner := New()
	calls := 0
	owner.launch = func(Spec) (*managedProcess, error) {
		calls++
		return nil, errors.Join(ErrInvalid, ErrReviewRequired)
	}
	observed, err := owner.Start(context.Background(), isolationTestSpec())
	if !errors.Is(err, ErrReviewRequired) || observed.State != StateReviewRequired ||
		observed.PID != 0 || observed.Generation != 0 {
		t.Fatal("input loss was not quarantined before launch:", observed, err)
	}
	if _, err := owner.Start(context.Background(), isolationTestSpec()); !errors.Is(err, ErrReviewRequired) || calls != 1 {
		t.Fatal("quarantined boundary was retried:", calls, err)
	}
	if stopped, err := owner.Stop(context.Background()); !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired {
		t.Fatal("cleanup cleared input-loss quarantine:", stopped, err)
	}
}

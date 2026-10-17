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
)

// Bookkeeping fixture only: actual retained file/process-set descriptors, no
// accepted runtime bundle, static executable qualification, mount or child.
func ownerCopyBookkeepingFixture(t *testing.T) (*Owner, *os.File) {
	t.Helper()
	program, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	set, err := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "unused", Process: processowner.Spec{
		Executable: "/fixed/unused", Ready: func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}, []*os.File{program})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	root := releaseFaultFile(t, false)
	owner := &Owner{gate: make(chan struct{}, 1), processes: set, retainedCode: &retainedCode{root: root}}
	owner.self = owner
	owner.snapshot.State = processowner.StateStopped
	return owner, root
}

func TestOwnerValueCopyCannotCloseOriginalReferences(t *testing.T) {
	owner, root := ownerCopyBookkeepingFixture(t)
	copied := *owner
	if err := copied.Close(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Error("value copy gained teardown authority", err)
	}
	if _, err := root.Stat(); err != nil {
		t.Error("value copy closed original retained reference", err)
	}
	if observed, err := owner.processes.Observe(context.Background()); err != nil || observed.State != processowner.StateStopped {
		t.Error("value copy changed original stopped process-set lifetime", observed.State, err)
	}
	if owner.closed || owner.review {
		t.Error("copy changed original lifecycle flags")
	}
	// Pointer aliases are the same original lifetime, not value copies. The
	// identity fence must not simply reject every Close and make this test pass.
	alias := owner
	if err := alias.Close(context.Background()); err != nil || !owner.closed {
		t.Fatal("original pointer alias lost teardown authority", err)
	}
	if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("verified original close did not release its pin", err)
	}
}

func TestOwnerCopiesCannotBypassReviewOrTouchOriginalGate(t *testing.T) {
	for _, review := range []bool{false, true} {
		for _, busy := range []bool{false, true} {
			owner, root := ownerCopyBookkeepingFixture(t)
			copied := *owner // Copy BEFORE original review, the dangerous fork.
			owner.review = review
			if review {
				owner.snapshot.State = processowner.StateReviewRequired
			}
			if busy {
				owner.gate <- struct{}{}
			}
			gateCount := 0
			if busy {
				gateCount = 1
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			for _, ctx := range []context.Context{context.Background(), canceled, nil} {
				for _, call := range []func() (OwnerSnapshot, error){
					func() (OwnerSnapshot, error) { return copied.Start(ctx) },
					func() (OwnerSnapshot, error) { return copied.Observe(ctx) },
					func() (OwnerSnapshot, error) { return copied.Supervise(ctx, time.Second) },
				} {
					observed, err := call()
					if !errors.Is(err, ErrUnavailable) || observed.State != "" || len(observed.Processes.Members) != 0 {
						t.Fatal("copied lifecycle observed or entered original authority", review, busy, observed.State, err)
					}
				}
				if err := copied.Close(ctx); !errors.Is(err, ErrUnavailable) {
					t.Fatal("copied teardown entered original authority", review, busy, err)
				}
			}
			if owner.review != review || owner.closed || len(owner.gate) != gateCount {
				t.Fatal("copy changed original flags or lifecycle gate")
			}
			if _, err := root.Stat(); err != nil {
				t.Fatal("copy released original reference", err)
			}
			if observed, err := owner.processes.Observe(context.Background()); err != nil || observed.State != processowner.StateStopped {
				t.Fatal("copy changed original process set", err)
			}
			if busy {
				<-owner.gate
			}
			closeErr := owner.Close(context.Background())
			if (review && !errors.Is(closeErr, ErrReviewRequired)) || (!review && closeErr != nil) {
				t.Fatal("original close changed review semantics", closeErr)
			}
		}
	}
}

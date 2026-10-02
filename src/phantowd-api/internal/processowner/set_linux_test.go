//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestSetStartupFailureStopsPreviouslyReadyMembers(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate test executable:", err)
	}
	stopOrderPath := t.TempDir() + "/stop-order"
	child := func(name string, ready ReadinessProbe, timeout time.Duration) Spec {
		return Spec{
			Executable: executable,
			Args:       []string{"-test.run=^TestSetStartupFailureStopsPreviouslyReadyMembers$", "--", "stop-marker", stopOrderPath, name},
			Ready:      ready, ReadyTimeout: timeout, ProbeInterval: 10 * time.Millisecond,
			StopTimeout: time.Second,
		}
	}
	set, err := NewSet([]MemberSpec{
		{Name: "smb", Process: child("smb", func(context.Context) (bool, error) { return true, nil }, time.Second)},
		{Name: "nfs", Process: child("nfs", func(context.Context) (bool, error) { return false, nil }, 80*time.Millisecond)},
	})
	if err != nil {
		t.Fatal("create fixed service set:", err)
	}
	snapshot, err := set.Start(context.Background())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("later member failure was not returned: snapshot=%+v err=%v", snapshot, err)
	}
	if snapshot.State != StateStopped || snapshot.Generation != 0 || len(snapshot.Members) != 2 {
		t.Fatalf("failed aggregate start was reported active or advanced its generation: %+v", snapshot)
	}
	if snapshot.Members[0].Name != "smb" || snapshot.Members[0].Process.State != StateStopped ||
		snapshot.Members[0].Process.Generation != 1 || snapshot.Members[0].Process.PID != 0 {
		t.Fatalf("previously ready member was not cleanly rolled back: %+v", snapshot.Members[0])
	}
	if snapshot.Members[1].Name != "nfs" || snapshot.Members[1].Process.State != StateStopped ||
		snapshot.Members[1].Process.Generation != 0 || snapshot.Members[1].Process.PID != 0 {
		t.Fatalf("failed member was not left stopped: %+v", snapshot.Members[1])
	}
	stopOrder, err := os.ReadFile(stopOrderPath)
	if err != nil || !bytes.Equal(stopOrder, []byte("nfs\nsmb\n")) {
		t.Fatalf("service rollback was not performed in reverse startup order: order=%q err=%v", stopOrder, err)
	}
}

func TestSetStartsAllFixedMembersAndStopsWithoutAdvancingGeneration(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate test executable:", err)
	}
	makeSpec := func() ([]string, Spec) {
		args := []string{"-test.run=^TestSetStartsAllFixedMembersAndStopsWithoutAdvancingGeneration$", "--", "wait"}
		return args, Spec{
			Executable: executable, Args: args,
			Ready:        func(context.Context) (bool, error) { return true, nil },
			ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
		}
	}
	firstArgs, first := makeSpec()
	secondArgs, second := makeSpec()
	set, err := NewSet([]MemberSpec{
		{Name: "smb", Process: first},
		{Name: "nfs", Process: second},
	})
	if err != nil {
		t.Fatal("create fixed service set:", err)
	}
	// The set owns immutable launch arguments after construction.
	firstArgs[2] = "exit"
	secondArgs[2] = "exit"
	started, err := set.Start(context.Background())
	if err != nil || started.State != StateReady || started.Generation != 1 || len(started.Members) != 2 {
		t.Fatalf("all fixed members did not become ready: snapshot=%+v err=%v", started, err)
	}
	if _, err := json.Marshal(started); err == nil {
		t.Fatal("internal process-set snapshot became serializable")
	}
	if err := json.Unmarshal([]byte(`{"state":"ready"}`), &SetSnapshot{}); err == nil {
		t.Fatal("internal process-set snapshot became deserializable")
	}
	for _, member := range started.Members {
		if member.Process.State != StateReady || member.Process.Generation != 1 || member.Process.PID <= 1 {
			t.Fatalf("member %q did not reach a new owned generation: %+v", member.Name, member.Process)
		}
	}
	stopped, err := set.Stop(context.Background())
	if err != nil || stopped.State != StateStopped || stopped.Generation != 1 || len(stopped.Members) != 2 {
		t.Fatalf("clean aggregate stop changed the generation or failed: snapshot=%+v err=%v", stopped, err)
	}
	for _, member := range stopped.Members {
		if member.Process.State != StateStopped || member.Process.Generation != 1 || member.Process.PID != 0 {
			t.Fatalf("member %q was not cleanly stopped: %+v", member.Name, member.Process)
		}
	}
}

func TestSetObservationQuarantinesUnexpectedMemberWithoutStoppingPeer(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate test executable:", err)
	}
	directory := t.TempDir()
	readyPath := directory + "/ready"
	releasePath := directory + "/release"
	exitedPath := directory + "/exited"
	set, err := NewSet([]MemberSpec{
		{
			Name: "smb",
			Process: Spec{
				Executable: executable,
				Args: []string{"-test.run=^TestSetObservationQuarantinesUnexpectedMemberWithoutStoppingPeer$", "--",
					"ready-exit", readyPath, releasePath, exitedPath},
				Ready: func(context.Context) (bool, error) {
					_, err := os.Stat(readyPath)
					return err == nil, nil
				},
				ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
			},
		},
		{
			Name: "nfs",
			Process: Spec{
				Executable:   executable,
				Args:         []string{"-test.run=^TestSetObservationQuarantinesUnexpectedMemberWithoutStoppingPeer$", "--", "wait"},
				Ready:        func(context.Context) (bool, error) { return true, nil },
				ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond,
				StopTimeout: time.Second,
			},
		},
	})
	if err != nil {
		t.Fatal("create fixed service set:", err)
	}
	t.Cleanup(func() { _, _ = set.Stop(context.Background()) })
	started, err := set.Start(context.Background())
	if err != nil || started.State != StateReady || started.Generation != 1 || len(started.Members) != 2 {
		t.Fatalf("fixed members did not all reach readiness: snapshot=%+v err=%v", started, err)
	}
	if err := os.WriteFile(releasePath, []byte("exit"), 0600); err != nil {
		t.Fatal("release controlled member:", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(exitedPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controlled member did not exit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		observed, observeErr := set.Observe(context.Background())
		if errors.Is(observeErr, ErrReviewRequired) {
			if observed.State != StateReviewRequired || observed.Generation != 1 ||
				observed.Members[0].Process.State != StateReviewRequired ||
				observed.Members[1].Process.State != StateReady || observed.Members[1].Process.PID <= 1 {
				t.Fatalf("unexpected member exit stopped or hid its healthy peer: %+v", observed)
			}
			break
		}
		if observeErr != nil || time.Now().After(deadline) {
			t.Fatalf("set did not observe the member exit: snapshot=%+v err=%v", observed, observeErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := set.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("set started a replacement member after review was required: %v", err)
	}
	stopped, err := set.Stop(context.Background())
	if !errors.Is(err, ErrReviewRequired) || stopped.State != StateReviewRequired || stopped.Generation != 1 {
		t.Fatalf("cleanup cleared member review state: snapshot=%+v err=%v", stopped, err)
	}
	for _, member := range stopped.Members {
		if member.Process.PID != 0 {
			t.Fatalf("Stop left member %q running after review: %+v", member.Name, member.Process)
		}
	}
}

func TestSetRequiresEveryNonRootMemberToUseTheHandoffGroup(t *testing.T) {
	groups := []uint32{1000}
	makeProcess := func(runAs *Credentials) Spec {
		return Spec{
			Executable: "/bin/busybox", RunAs: runAs,
			Ready:        func(context.Context) (bool, error) { return false, nil },
			ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
		}
	}
	set, err := NewSet([]MemberSpec{
		{Name: "primary-group", Process: makeProcess(&Credentials{UID: 1000, GID: 1000})},
		{Name: "supplementary-group", Process: makeProcess(&Credentials{UID: 1001, GID: 1001, SupplementaryGIDs: groups})},
	})
	if err != nil {
		t.Fatal("create fixed non-root service set:", err)
	}
	groups[0] = 1002
	if !set.AllMembersRunAsNonRootWithGroup(1000) {
		t.Fatal("set lost its copied handoff-group membership or rejected a primary-group member")
	}
	if set.AllMembersRunAsNonRootWithGroup(1001) {
		t.Fatal("set authorized a group not shared by every member")
	}

	for name, runAs := range map[string]*Credentials{
		"implicit":     nil,
		"root":         {UID: 0, GID: 1000},
		"system-group": {UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{0}},
	} {
		invalid, err := NewSet([]MemberSpec{{Name: "candidate", Process: makeProcess(runAs)}})
		if err != nil {
			t.Fatalf("create %s test set: %v", name, err)
		}
		if invalid.AllMembersRunAsNonRootWithGroup(1000) {
			t.Fatalf("set authorized %s for a service handoff", name)
		}
	}
}

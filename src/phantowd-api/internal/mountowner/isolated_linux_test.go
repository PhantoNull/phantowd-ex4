//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func isolatedRuntimeTestSpec() processowner.Spec {
	return processowner.Spec{Executable: "/fixed/child", Args: []string{"fixed"},
		RunAs:        &processowner.Credentials{UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{1001}},
		Ready:        func(context.Context) (bool, error) { return false, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
}

func TestIsolatedRuntimeCopiesInputsAndExclusivelyClaimsHandoff(t *testing.T) {
	handoff := &ServiceHandoff{state: ServiceHandoffPrepared, serviceGroupID: 1000}
	spec := isolatedRuntimeTestSpec()
	runtime, err := NewIsolatedServiceRuntime(handoff, spec, "/fixed/launcher")
	if err != nil {
		t.Fatal(err)
	}
	spec.Args[0] = "replacement"
	spec.RunAs.UID = 0
	spec.RunAs.SupplementaryGIDs[0] = 0
	if runtime.process.spec.Args[0] != "fixed" || runtime.process.spec.RunAs.UID != 1000 ||
		runtime.process.spec.RunAs.SupplementaryGIDs[0] != 1001 || !handoff.isolatedReserved {
		t.Fatal("mutable caller inputs remained launch authority")
	}
	if _, err := NewIsolatedServiceRuntime(handoff, isolatedRuntimeTestSpec(), "/fixed/launcher"); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatal("a second isolated runtime claimed the handoff")
	}
	set, err := processowner.NewSet([]processowner.MemberSpec{{Name: "service", Process: isolatedRuntimeTestSpec()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServiceRuntime(handoff, set); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatal("ordinary runtime bypassed exclusive isolated claim")
	}
}

func TestOrdinaryRuntimeClaimCannotBeReusedForIsolatedChild(t *testing.T) {
	handoff := &ServiceHandoff{state: ServiceHandoffPrepared, serviceGroupID: 1000}
	set, _ := processowner.NewSet([]processowner.MemberSpec{{Name: "service", Process: isolatedRuntimeTestSpec()}})
	if _, err := NewServiceRuntime(handoff, set); err != nil {
		t.Fatal(err)
	}
	if _, err := NewIsolatedServiceRuntime(handoff, isolatedRuntimeTestSpec(), "/fixed/launcher"); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatal("isolated runtime stole an ordinary runtime's handoff")
	}
}

func TestInvalidIsolatedRuntimeDoesNotClaimHandoff(t *testing.T) {
	for _, input := range []struct {
		name     string
		launcher string
		edit     func(*processowner.Spec)
	}{
		{"relative-launcher", "relative", func(*processowner.Spec) {}},
		{"noncanonical-launcher", "/fixed/../launcher", func(*processowner.Spec) {}},
		{"root-user", "/fixed/launcher", func(s *processowner.Spec) { s.RunAs.UID = 0 }},
		{"wrong-group", "/fixed/launcher", func(s *processowner.Spec) { s.RunAs.GID = 1002 }},
		{"missing-identity", "/fixed/launcher", func(s *processowner.Spec) { s.RunAs = nil }},
	} {
		t.Run(input.name, func(t *testing.T) {
			handoff := &ServiceHandoff{state: ServiceHandoffPrepared, serviceGroupID: 1000}
			spec := isolatedRuntimeTestSpec()
			input.edit(&spec)
			if _, err := NewIsolatedServiceRuntime(handoff, spec, input.launcher); !errors.Is(err, ErrServiceRuntimeInvalid) || handoff.runtimeReserved {
				t.Fatal("invalid fixed inputs changed handoff ownership:", err)
			}
		})
	}
	for _, state := range []ServiceHandoffState{ServiceHandoffActive, ServiceHandoffReview, ServiceHandoffClosed} {
		handoff := &ServiceHandoff{state: state, serviceGroupID: 1000}
		if _, err := NewIsolatedServiceRuntime(handoff, isolatedRuntimeTestSpec(), "/fixed/launcher"); !errors.Is(err, ErrServiceRuntimeInvalid) || handoff.runtimeReserved {
			t.Fatal("non-prepared handoff was claimed:", state, err)
		}
	}
}

func TestIsolatedPinBlocksHandoffTeardownWithoutMutation(t *testing.T) {
	handoff := &ServiceHandoff{state: ServiceHandoffActive, isolatedPins: 1}
	if err := handoff.Close(); !errors.Is(err, ErrHandoffBusy) || handoff.state != ServiceHandoffActive || handoff.reviewRequired {
		t.Fatal("handoff teardown was not refused before touching resources:", err)
	}
}

func TestRestrictedRootCensusRejectsAnythingBeyondDeclaredShares(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "media"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	handoff := &ServiceHandoff{root: root, members: []handoffMember{{shareID: "media"}}}
	if err := handoff.verifyRestrictedContentsLocked(); err != nil {
		t.Fatal("exact declared root refused:", err)
	}
	for _, extra := range []string{"private", "proc", ".hidden"} {
		path := filepath.Join(rootPath, extra)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(handoff.verifyRestrictedContentsLocked(), ErrHandoffReview) {
			t.Fatal("undeclared root directory accepted:", extra)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(rootPath, "media")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(handoff.verifyRestrictedContentsLocked(), ErrHandoffReview) {
		t.Fatal("missing declared share accepted")
	}
	if err := os.Symlink(rootPath, path); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(handoff.verifyRestrictedContentsLocked(), ErrHandoffReview) {
		t.Fatal("symlink grant accepted")
	}
}

func TestIsolatedRuntimeUnavailableAndNotSerializable(t *testing.T) {
	if _, err := json.Marshal(IsolatedServiceRuntime{}); err == nil {
		t.Fatal("runtime serialized")
	}
	var runtime IsolatedServiceRuntime
	if err := json.Unmarshal([]byte(`{}`), &runtime); err == nil {
		t.Fatal("runtime deserialized")
	}
	for _, item := range []*IsolatedServiceRuntime{nil, {}} {
		if _, err := item.Start(context.Background()); !errors.Is(err, ErrServiceRuntimeUnavailable) {
			t.Fatal(err)
		}
		if _, err := item.Stop(context.Background()); !errors.Is(err, ErrServiceRuntimeUnavailable) {
			t.Fatal(err)
		}
		if _, err := item.Observe(context.Background()); !errors.Is(err, ErrServiceRuntimeUnavailable) || item.Diagnostics() != nil {
			t.Fatal(err)
		}
	}
}

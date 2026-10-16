//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A prospective operation coordinator must retain the actual policy-directory
// lock. Neither a common ancestor nor a sibling's lock excludes today's Store.
// This is a kernel/adapter qualification on temporary files, not a coordinator.
func TestBootstrapParentAndSiblingLocksDoNotReplaceOriginalPolicyLock(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "policy")
	operations := filepath.Join(root, "operations")
	for _, directory := range []string{policy, operations} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{root, operations} {
		fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := unix.Close(fd); err != nil {
				t.Error(err)
			}
		})
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
	}
	// Both common-root and sibling locks are held, but the existing policy Store
	// still enters. Its own lock is the authority that must not be substituted.
	s, err := OpenWithCodec(policy, nasKillCodec())
	if err != nil {
		t.Fatal("ancestor/sibling unexpectedly replaced policy lock", err)
	}
	if err := s.Commit(0, nasKillPolicy(1)); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	probeIndependentPolicyOpen(t, policy, "allowed")
	a, err := OpenBootstrapAuthorityWithCodec(context.Background(), policy, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	for range 3 {
		if got, err := a.Observe(context.Background()); err != nil || got.Kind != BootstrapValidCurrentPolicy {
			t.Fatal("original retained policy observation failed", got, err)
		}
		other, err := OpenWithCodec(policy, nasKillCodec())
		if other != nil {
			other.Close()
		}
		if !errors.Is(err, ErrBusy) {
			t.Fatal("original lock failed to exclude policy writer", err)
		}
	}
	probeIndependentPolicyOpen(t, policy, "busy")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Ancestor/sibling locks still exist: releasing the actual policy observer
	// admits a writer again. Closing and reopening would introduce a real gap.
	s, err = OpenWithCodec(policy, nasKillCodec())
	if err != nil {
		t.Fatal("unexpected exclusion after actual policy lock release", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	probeIndependentPolicyOpen(t, policy, "allowed")
}

func probeIndependentPolicyOpen(t *testing.T, directory, mode string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestBootstrapPolicyLockIndependentProcessProbe$", "-test.count=1")
	command.WaitDelay = time.Second
	command.Env = append(os.Environ(), "PHANTOWD_POLICY_LOCK_PROBE_MODE="+mode, "PHANTOWD_POLICY_LOCK_PROBE_DIRECTORY="+directory)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("independent policy lock probe did not verify", mode, err)
	}
	if ctx.Err() != nil {
		t.Fatal("independent policy lock probe exceeded its original deadline")
	}
	if !validIndependentPolicyProbeOutput(output, mode) {
		t.Fatal("independent policy lock probe receipt missing, duplicate or incorrect")
	}
}

func validIndependentPolicyProbeOutput(output []byte, mode string) bool {
	if len(output) > 8192 || (mode != "allowed" && mode != "busy") {
		return false
	}
	expected := "PHANTOWD_POLICY_LOCK_PROBE mode=" + mode + " original_store=true independent_process=true"
	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSuffix(line, "\r") == expected {
			count++
		}
	}
	return count == 1
}

func TestIndependentPolicyProbeOutputRequiresExactUniqueReceipt(t *testing.T) {
	for _, mode := range []string{"allowed", "busy"} {
		marker := "PHANTOWD_POLICY_LOCK_PROBE mode=" + mode + " original_store=true independent_process=true"
		if !validIndependentPolicyProbeOutput([]byte(marker+"\r\nPASS\n"), mode) {
			t.Fatal("exact fixture receipt rejected")
		}
		for _, output := range []string{"", "PASS\n", "testing: warning: no tests to run\nPASS\n", marker + " extra\n", marker + "\n" + marker + "\n", strings.Repeat("x", 8193) + marker + "\n"} {
			if validIndependentPolicyProbeOutput([]byte(output), mode) {
				t.Fatal("unverified child receipt admitted")
			}
		}
		if validIndependentPolicyProbeOutput([]byte(marker+"\n"), "other") {
			t.Fatal("invalid fixture mode")
		}
	}
}

// Test-binary-only helper: the parent supplies only its own disposable directory.
// CLOEXEC locks are not inherited; the child opens the actual Store independently.
func TestBootstrapPolicyLockIndependentProcessProbe(t *testing.T) {
	mode := os.Getenv("PHANTOWD_POLICY_LOCK_PROBE_MODE")
	if mode == "" {
		t.Skip("owned subprocess fixture only")
	}
	if mode != "allowed" && mode != "busy" {
		t.Fatal("invalid fixture mode")
	}
	directory := os.Getenv("PHANTOWD_POLICY_LOCK_PROBE_DIRECTORY")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(directory) != "policy" {
		t.Fatal("invalid disposable policy fixture")
	}
	s, err := OpenWithCodec(directory, nasKillCodec())
	if s != nil {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatal("independent fixture close failed")
		}
	}
	if mode == "busy" {
		if !errors.Is(err, ErrBusy) {
			t.Fatal("original policy lock did not exclude independent process")
		}
	} else if err != nil {
		t.Fatal("ancestor/sibling locks excluded independent process unexpectedly")
	}
	fmt.Println("PHANTOWD_POLICY_LOCK_PROBE mode=" + mode + " original_store=true independent_process=true")
}

//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestQEMUNFSRebootKernelProfileAcceptsExactRunningAndStoppedStates(t *testing.T) {
	for _, state := range []struct {
		running bool
		threads string
		ports   string
	}{{true, "2\n", "tcp 2049\n"}, {false, "0\n", ""}} {
		if err := validateQEMUNFSKernelProfile([]byte(state.threads), []byte("+3\n"), []byte(state.ports), state.running); err != nil {
			t.Fatal("exact disposable kernel profile refused", state.running, err)
		}
	}
}

func TestQEMUNFSRebootKernelProfileRefusesIncompleteOrBroadenedStates(t *testing.T) {
	for _, running := range []bool{false, true} {
		threads, ports := "0\n", ""
		if running {
			threads, ports = "2\n", "tcp 2049\n"
		}
		for _, changed := range []string{"", "0", "2", "02\n", "1\n", "3\n", "-1\n", "2\n0\n", "2\r\n", strings.Repeat("2", 4097)} {
			if changed == threads {
				continue
			}
			if validateQEMUNFSKernelProfile([]byte(changed), []byte("+3\n"), []byte(ports), running) == nil {
				t.Fatal("missing, partial or unexpected thread state admitted", running)
			}
		}
		for _, changed := range []string{"", "+3", "+2 +3\n", "+3 +4\n", "+3 -4\n", "-3\n", "+3 +3\n", "+3\n+4\n", "+3\r\n", strings.Repeat("+3 ", 1366)} {
			if validateQEMUNFSKernelProfile([]byte(threads), []byte(changed), []byte(ports), running) == nil {
				t.Fatal("missing, unknown or broadened protocol profile admitted", running)
			}
		}
		for _, changed := range []string{"", "tcp 2049", "tcp6 2049\n", "udp 2049\n", "rdma 2049\n", "tcp 2050\n",
			"tcp 2049\n", "tcp 2049\nudp 2049\n", "tcp 2049\ntcp 2049\n", "tcp 2049\r\n", strings.Repeat("tcp 2049\n", 456)} {
			if changed == ports {
				continue
			}
			if validateQEMUNFSKernelProfile([]byte(threads), []byte("+3\n"), []byte(changed), running) == nil {
				t.Fatal("missing, residual or unexpected listener admitted", running)
			}
		}
	}
}

func TestQEMUNFSRebootRuntimeRefusesHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("native-host refusal is separate from the guarded ARM guest")
	}
	for _, phase := range []string{"unknown", "seed", "verify"} {
		if err := exerciseQEMUNFSReboot(phase); err == nil {
			t.Fatal("native host admitted as the disposable NFS reboot guest", phase)
		}
	}
}

func TestQEMUNFSRebootBindingRefusalsKeepOriginalPolicyUsable(t *testing.T) {
	policy, err := prepareQEMUNFSRebootPolicy(t.TempDir(), "seed")
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	if err := verifyQEMUNFSRebootBindingRefusal(policy); err != nil {
		t.Fatal("fixture binding refusal did not preserve its current policy", err)
	}
}

func TestQEMUNFSRebootPolicy(t *testing.T) {
	root := t.TempDir()
	first, err := prepareQEMUNFSRebootPolicy(root, "seed")
	if err != nil || len(first.Exports) != 3 || first.Revision != 1 {
		t.Fatal("fresh confirmed NFS fixture policy unavailable", err)
	}
	before, err := os.ReadFile(root + "/nfs-reboot/policy/nas-services.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := prepareQEMUNFSRebootPolicy(root, "verify")
	if err != nil || !reflect.DeepEqual(first.Preview, second.Preview) {
		t.Fatal("reboot changed the confirmed export definitions", err)
	}
	defer second.Close()
	after, err := os.ReadFile(root + "/nfs-reboot/policy/nas-services.json")
	if err != nil || string(before) != string(after) {
		t.Fatal("verification rewrote policy")
	}
}

func TestQEMUNFSRebootPolicyChangedStateStaysRefused(t *testing.T) {
	root := t.TempDir()
	policy, err := prepareQEMUNFSRebootPolicy(root, "seed")
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	path := root + "/nfs-reboot/policy/nas-services.json"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := qemuNFSRebootConfig()
	changed.FileServices.NFS.Exports[0].Clients[0].Access = "ro"
	wire, err := json.Marshal(changed)
	if err != nil || os.WriteFile(path, wire, 0600) != nil {
		t.Fatal("cannot prepare changed synthetic policy", err)
	}
	if policy.Check() == nil {
		t.Fatal("changed policy admitted")
	}
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if policy.Check() == nil {
		t.Fatal("restoration revived the failed fixture lifetime")
	}
}

func TestQEMUNFSRebootPolicyPendingEvidenceRefused(t *testing.T) {
	root := t.TempDir()
	policy, err := prepareQEMUNFSRebootPolicy(root, "seed")
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	path := root + "/nfs-reboot/policy/.nas-services.pending"
	const evidence = "interrupted synthetic operation"
	if err := os.WriteFile(path, []byte(evidence), 0600); err != nil {
		t.Fatal(err)
	}
	if policy.Check() == nil {
		t.Fatal("pending evidence admitted during fixture lifetime")
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := prepareQEMUNFSRebootPolicy(root, "verify"); err == nil {
		reopened.Close()
		t.Fatal("pending evidence admitted after reboot")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != evidence {
		t.Fatal("pending evidence changed", err)
	}
}

func TestQEMUNFSRebootPolicyNeverInitializesVerification(t *testing.T) {
	for _, phase := range []string{"verify", "unknown"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			if policy, err := prepareQEMUNFSRebootPolicy(root, phase); err == nil {
				policy.Close()
				t.Fatal("absent/unknown fixture accepted")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("verification initialized state", err)
			}
		})
	}
}

func TestQEMUNFSRebootPolicyRetainsWriterLock(t *testing.T) {
	root := t.TempDir()
	policy, err := prepareQEMUNFSRebootPolicy(root, "seed")
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	for _, phase := range []string{"seed", "verify"} {
		if concurrent, err := prepareQEMUNFSRebootPolicy(root, phase); err == nil {
			concurrent.Close()
			t.Fatal("concurrent fixture admitted", phase)
		}
		if err := policy.Check(); err != nil {
			t.Fatal("refused concurrent opener damaged current policy", err)
		}
	}
	if err := policy.Close(); err != nil {
		t.Fatal(err)
	}
	if policy.Check() == nil {
		t.Fatal("closed lifetime admitted")
	}
	reopened, err := prepareQEMUNFSRebootPolicy(root, "verify")
	if err != nil {
		t.Fatal("clean new lifetime refused", err)
	}
	defer reopened.Close()
	if err := reopened.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestQEMUNFSRebootPolicyRejectsForeignOrCorruptState(t *testing.T) {
	for _, kind := range []string{"unknown-entry", "corrupt-current", "changed-current"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			policy, err := prepareQEMUNFSRebootPolicy(root, "seed")
			if err != nil {
				t.Fatal(err)
			}
			if err := policy.Close(); err != nil {
				t.Fatal(err)
			}
			path := root + "/nfs-reboot/policy/nas-services.json"
			payload := []byte("{truncated")
			if kind == "unknown-entry" {
				path = root + "/nfs-reboot/policy/unrecognized-evidence"
			} else if kind == "changed-current" {
				changed := qemuNFSRebootConfig()
				changed.FileServices.NFS.Exports[0].Clients[0].Access = "ro"
				payload, err = json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := prepareQEMUNFSRebootPolicy(root, "verify"); err == nil {
				reopened.Close()
				t.Fatal("unconfirmed state admitted")
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != string(payload) {
				t.Fatal("refusal changed evidence", err)
			}
		})
	}
}

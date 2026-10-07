//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"testing"
)

func TestNativeDataDaemonRefusesHostAndPreservesCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal; disposable ARMv5 fixture proves data handoff")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	spec := MemberSpec{Name: "native-samba-data", Process: Spec{Executable: "/usr/sbin/phantowd-samba-root-launcher", Args: []string{"native-data-server"}, RunAs: &Credentials{UID: 0, GID: 0}}}
	for range 16 {
		set, err := NewNativeSambaDataPinnedSetQEMU(spec, caller, [5]*os.File{caller, caller, caller, caller, caller}, [7]*os.File{caller, caller, caller, caller, caller, caller, caller}, [2]*os.File{caller, caller})
		if set != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired data daemon authority", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("host refusal consumed caller", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("data daemon refusal leaked descriptors", err)
	}
}

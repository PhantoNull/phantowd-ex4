// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUMDCommandsSelectModeBeforeConfig(t *testing.T) {
	tests := []struct {
		name string
		mode string
		args []string
	}{
		{name: "create", mode: "--create", args: qemuMDCreateArguments()},
		{name: "stop", mode: "--stop", args: qemuMDStopArguments()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.args) < 2 || test.args[0] != test.mode || test.args[1] != "--config=/dev/null" {
				t.Fatalf("mdadm must select its operation before config: args=%q", test.args)
			}
		})
	}
}

func TestQEMUMDV10CreateTargetsOnlyTheTwoFixedDisposableGPTPartitions(t *testing.T) {
	args := qemuMDV10CreateArguments()
	if len(args) < 2 || args[0] != "--create" || args[1] != "--config=/dev/null" {
		t.Fatalf("mdadm must select create before disabling its system config: args=%q", args)
	}
	for _, required := range []string{"--metadata=1.0", "--level=raid1", "--raid-devices=2", "--assume-clean"} {
		if !containsString(args, required) {
			t.Fatalf("MD v1.0 fixture omitted %q: args=%q", required, args)
		}
	}
	if args[len(args)-2] != "/dev/sdb1" || args[len(args)-1] != "/dev/sdc1" {
		t.Fatalf("MD v1.0 creation must target only partition 1 of its two fixed QEMU disks: args=%q", args)
	}
	for _, forbidden := range []string{"/dev/sda", "/dev/sda1", "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/sde", "/dev/sdf"} {
		if containsString(args, forbidden) {
			t.Fatalf("MD v1.0 fixture included a whole disk or unrelated device %q: args=%q", forbidden, args)
		}
	}
}

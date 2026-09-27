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

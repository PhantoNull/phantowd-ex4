// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestClassifyGPTPartitionTypeGUID(t *testing.T) {
	tests := []struct {
		name string
		guid string
		want gptPartitionTypeHint
	}{
		{name: "UEFI system", guid: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", want: gptTypeHintEFISystem},
		{name: "uppercase GUID", guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", want: gptTypeHintEFISystem},
		{name: "Linux data", guid: "0fc63daf-8483-4772-8e79-3d69d8477de4", want: gptTypeHintLinuxData},
		{name: "Linux RAID member", guid: "a19d880f-05fc-4d3b-a006-743f0f84911e", want: gptTypeHintLinuxRAID},
		{name: "Linux swap", guid: "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", want: gptTypeHintLinuxSwap},
		{name: "Linux LVM", guid: "e6d6d379-f507-44c2-a23c-238f2a3df928", want: gptTypeHintLinuxLVM},
		{name: "unknown valid type", guid: "11111111-2222-3333-4444-555555555555", want: gptTypeHintUnknown},
		{name: "invalid type", guid: "not-a-guid", want: gptTypeHintUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyGPTPartitionTypeGUID(test.guid); got != test.want {
				t.Fatalf("classifyGPTPartitionTypeGUID(%q) = %q, want %q", test.guid, got, test.want)
			}
		})
	}
}

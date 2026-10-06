// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "strings"

// gptPartitionTypeHint is a generic label for a GPT-declared type GUID. It is
// not evidence about bytes stored in a partition and never qualifies a WD
// layout for import, assembly, mount, or mutation.
type gptPartitionTypeHint string

const (
	gptTypeHintUnknown   gptPartitionTypeHint = "unknown"
	gptTypeHintEFISystem gptPartitionTypeHint = "efi-system"
	gptTypeHintLinuxData gptPartitionTypeHint = "linux-data"
	gptTypeHintLinuxRAID gptPartitionTypeHint = "linux-raid-member"
	gptTypeHintLinuxSwap gptPartitionTypeHint = "linux-swap"
	gptTypeHintLinuxLVM  gptPartitionTypeHint = "linux-lvm"
)

// classifyGPTPartitionTypeGUID maps only a small, explicit set of well-known
// type GUIDs. Unknown, malformed, or vendor-specific values stay unknown.
func classifyGPTPartitionTypeGUID(guid string) gptPartitionTypeHint {
	switch strings.ToLower(guid) {
	case "c12a7328-f81f-11d2-ba4b-00a0c93ec93b":
		return gptTypeHintEFISystem
	case "0fc63daf-8483-4772-8e79-3d69d8477de4":
		return gptTypeHintLinuxData
	case "a19d880f-05fc-4d3b-a006-743f0f84911e":
		return gptTypeHintLinuxRAID
	case "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f":
		return gptTypeHintLinuxSwap
	case "e6d6d379-f507-44c2-a23c-238f2a3df928":
		return gptTypeHintLinuxLVM
	default:
		return gptTypeHintUnknown
	}
}

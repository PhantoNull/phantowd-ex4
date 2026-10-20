//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import "strings"

// Supplement to the exact independent-peer profile, never standalone authority.
func parseOwnerStopLossSelector(data []byte) (selected, valid bool) {
	if len(data) > 4096 {
		return false, false
	}
	count := 0
	for _, word := range strings.Fields(string(data)) {
		if strings.HasPrefix(word, "phantowd_nfs_source_owner_stop_loss_fixture=") {
			selected = true
			if word != "phantowd_nfs_source_owner_stop_loss_fixture=1" {
				return true, false
			}
			count++
		}
	}
	if !selected {
		return false, true
	}
	peer, valid := parseOwnerDaemonLossSelector(data)
	return true, count == 1 && peer && valid
}

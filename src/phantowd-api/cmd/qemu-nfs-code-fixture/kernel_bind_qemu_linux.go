//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import "strings"

// The dedicated guest init chooses this scenario, not cleanup authority.
// Lower cleanup must establish the real original kernel/resource frontier.
func parseKernelBindSelectorQEMU(command []byte) (selected, valid bool) {
	if len(command) > 4096 || strings.IndexByte(string(command), 0) >= 0 {
		return false, false
	}
	code, source, inits, bad := 0, 0, 0, false
	for _, word := range strings.FieldsFunc(string(command), func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		if strings.HasPrefix(word, "init=") {
			inits++
			selected = selected || word == "init=/usr/sbin/phantowd-nfs-kernel-bind-init"
		}
		switch word {
		case "phantowd_nfs_code_fixture=1":
			code++
		case "phantowd_nfs_source_fixture=1":
			source++
		default:
			bad = bad || strings.HasPrefix(word, "phantowd_nfs_")
		}
	}
	if !selected {
		return false, true
	}
	return true, code == 1 && source == 1 && inits == 1 && !bad
}

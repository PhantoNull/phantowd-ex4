//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package processowner

import "strings"

const (
	nfsFaultCodeQEMU = iota
	nfsFaultSourceQEMU
	nfsFaultSourceLossQEMU
	nfsFaultSourcePeerQEMU
	nfsFaultOwnerPeerQEMU
	nfsFaultOwnerStopQEMU
)

// Pure closed grammar for the dedicated fault/withdrawal roles only. Ordinary
// source roles still admit their distinct profiles. This grants no authority.
func nfsFaultFlagsQEMU(command []byte) (flags [6]bool, valid bool) {
	if len(command) == 0 || len(command) > 4096 || strings.IndexByte(string(command), 0) >= 0 {
		return flags, false
	}
	for _, word := range strings.FieldsFunc(string(command), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		index := -1
		for candidate, value := range [...]string{
			"phantowd_nfs_code_fixture=1", "phantowd_nfs_source_fixture=1",
			"phantowd_nfs_source_loss_fixture=1", "phantowd_nfs_source_daemon_loss_fixture=1",
			"phantowd_nfs_source_owner_daemon_loss_fixture=1", "phantowd_nfs_source_owner_stop_loss_fixture=1",
		} {
			if word == value {
				index = candidate
				break
			}
		}
		if index >= 0 {
			if flags[index] {
				return [6]bool{}, false
			}
			flags[index] = true
		} else if strings.HasPrefix(word, "phantowd_nfs_") {
			return [6]bool{}, false
		}
	}
	return flags, true
}

func nfsSourceCleanupCommandQEMU(command []byte) bool {
	flags, valid := nfsFaultFlagsQEMU(command)
	return valid && flags[nfsFaultCodeQEMU] && flags[nfsFaultSourceQEMU] && flags[nfsFaultSourceLossQEMU] &&
		!flags[nfsFaultOwnerPeerQEMU] && !flags[nfsFaultOwnerStopQEMU]
}

func nfsSourcePeerCommandQEMU(command []byte) bool {
	flags, valid := nfsFaultFlagsQEMU(command)
	return valid && flags[nfsFaultCodeQEMU] && flags[nfsFaultSourceQEMU] && flags[nfsFaultSourceLossQEMU] &&
		flags[nfsFaultSourcePeerQEMU] && !flags[nfsFaultOwnerPeerQEMU] && !flags[nfsFaultOwnerStopQEMU]
}

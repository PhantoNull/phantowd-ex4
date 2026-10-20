//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package processowner

import (
	"context"
	"os"
	"strings"
)

func nfsServerPeerCommandQEMU(command []byte) bool {
	if len(command) > 4096 {
		return false
	}
	counts := [3]int{}
	for _, word := range strings.Fields(string(command)) {
		for index, prefix := range []string{"phantowd_nfs_code_fixture=", "phantowd_nfs_source_fixture=", "phantowd_nfs_source_owner_daemon_loss_fixture="} {
			if strings.HasPrefix(word, prefix) {
				if word != prefix+"1" {
					return false
				}
				counts[index]++
			}
		}
		for _, prefix := range []string{"phantowd_nfs_source_loss_fixture=", "phantowd_nfs_source_daemon_loss_fixture=", "phantowd_nfs_source_owner_policy_loss_fixture="} {
			if strings.HasPrefix(word, prefix) {
				return false
			}
		}
	}
	return counts == [3]int{1, 1, 1}
}

func nfsServerPeerFaultGuardQEMU() bool {
	if !nfsSourceFixtureGuardQEMU() {
		return false
	}
	command, err := os.ReadFile("/proc/cmdline")
	return err == nil && nfsServerPeerCommandQEMU(command)
}

// Dedicated independent-loss fixture only. Fixed original child/TERM; no PID,
// signal, executable or backend comes from the caller. Generic launchers and
// the old combined source-loss selector remain unchanged.
func (s *PinnedSet) InterruptNFSServerMountdFixtureQEMU(ctx context.Context) error {
	if !nfsServerPeerFaultGuardQEMU() {
		return ErrInvalid
	}
	return s.interruptNFSSourceMountdQEMU(ctx)
}

// Read-only original-source witness after Stop, not fault-injection authority.
// It requires the fixed ARMv5/source fixture and the original completed Stop,
// retained pins, generation and review. No signal, retry or release is admitted.
func (s *PinnedSet) CheckNFSServerMountdReviewStopQEMU(ctx context.Context) error {
	if !nfsSourceFixtureGuardQEMU() {
		return ErrInvalid
	}
	return s.checkNFSSourceMountdReviewStopQEMU(ctx)
}

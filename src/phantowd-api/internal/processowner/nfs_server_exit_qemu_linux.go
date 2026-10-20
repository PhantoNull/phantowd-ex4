//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package processowner

import (
	"context"
	"os"
)

func nfsServerPeerCommandQEMU(command []byte) bool {
	flags, valid := nfsFaultFlagsQEMU(command)
	return valid && flags[nfsFaultCodeQEMU] && flags[nfsFaultSourceQEMU] && flags[nfsFaultOwnerPeerQEMU] &&
		!flags[nfsFaultSourceLossQEMU] && !flags[nfsFaultSourcePeerQEMU]
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
// fixed role ABIs are unchanged; fault-profile selection is closed.
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

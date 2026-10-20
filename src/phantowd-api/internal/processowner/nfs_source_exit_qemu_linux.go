//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"syscall"
)

func nfsSourcePeerFaultGuardQEMU() bool {
	if !nfsSourceFixtureGuardQEMU() {
		return false
	}
	command, err := os.ReadFile("/proc/cmdline")
	return err == nil && nfsSourcePeerCommandQEMU(command)
}

// Fixed fault injection into THIS original fixture child only. No PID, signal,
// backend or command selector is accepted. The containing consumer permits one
// attempt; no generic launcher/Owner behavior or product surface is changed.
func (s *PinnedSet) InterruptNFSSourceMountdFixtureQEMU(ctx context.Context) error {
	if !nfsSourcePeerFaultGuardQEMU() {
		return ErrInvalid
	}
	return s.interruptNFSSourceMountdQEMU(ctx)
}

func (s *PinnedSet) interruptNFSSourceMountdQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if err := s.set.enter(ctx); err != nil {
		return err
	}
	defer s.set.leave()
	if len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "nfs-source-mountd" ||
		s.set.generation != 1 || s.set.state != StateReady || s.set.reviewRequired || s.releaseErr != nil {
		return ErrInvalid
	}
	owner := s.set.members[0].owner
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer owner.leave()
	p := owner.current
	if owner.generation != 1 || owner.state != StateReady || owner.reviewRequired || p == nil || !p.ready || p.exited() || p.stopAttempted ||
		p.command == nil || p.command.Process == nil || p.done == nil || p.pid <= 1 || p.command.Process.Pid != p.pid ||
		NFSSourceMountdAccessHandoffQEMU(p.diagnostics.snapshot(), false) != nil {
		return ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-p.done:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Read-only witness AFTER the original Stop has verified Wait/group absence.
// A review error is preserved, not treated as successful normal retirement.
// No signal, Stop/Close retry, release or restart is performed here.
func (s *PinnedSet) CheckNFSSourceMountdReviewStopQEMU(ctx context.Context) error {
	if !nfsSourcePeerFaultGuardQEMU() {
		return ErrInvalid
	}
	return s.checkNFSSourceMountdReviewStopQEMU(ctx)
}

func (s *PinnedSet) checkNFSSourceMountdReviewStopQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "nfs-source-mountd" || s.set.generation != 1 ||
		!s.set.reviewRequired || s.set.state != StateReviewRequired || s.releaseErr != nil {
		return ErrReviewRequired
	}
	owner := s.set.members[0].owner
	if owner == nil || !owner.reviewRequired || owner.current != nil || owner.generation != 1 {
		return ErrReviewRequired
	}
	state, err := s.set.Observe(ctx)
	if !errors.Is(err, ErrReviewRequired) || state.State != StateReviewRequired || state.Generation != 1 || len(state.Members) != 1 ||
		state.Members[0].Process.State != StateReviewRequired || state.Members[0].Process.Generation != 1 ||
		state.Members[0].Process.PID != 0 || state.Members[0].Process.DiagnosticsTruncated || owner.current != nil {
		return ErrReviewRequired
	}
	for _, pin := range s.pins {
		if pin == nil {
			return ErrReviewRequired
		}
		if _, err := pin.Stat(); err != nil {
			return errors.Join(ErrReviewRequired, err)
		}
	}
	return ctx.Err()
}

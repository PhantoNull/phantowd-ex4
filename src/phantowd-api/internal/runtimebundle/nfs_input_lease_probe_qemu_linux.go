//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

var nfsInputLeaseProbeRetainedQEMU *NFSInputLeaseQEMU

// Exercises only an unstarted reservation of the ORIGINAL fixture inputs.
// No descriptor is returned, no process/kernel admission is performed here.
func probeNFSInputLeaseQEMU(ctx context.Context, inputs *NFSInputsQEMU, candidate fileserviceplan.NFSv3Candidate) error {
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	changed, err := nfsInputsFixtureCandidateWithGenerationQEMU("127.0.0.1/32", 2)
	if err != nil {
		return err
	}
	_, originalTable, _, _ := candidate.Documents()
	_, changedTable, _, _ := changed.Documents()
	if originalTable != changedTable || candidate.EquivalentTo(changed) {
		return errors.New("same-text different-evidence fixture invalid")
	}
	if value, err := NewNFSInputLeaseQEMU(ctx, inputs, changed); value != nil || !errors.Is(err, ErrMismatch) || inputs.Check(ctx) != nil {
		return errors.New("same-text changed-evidence reservation admitted or poisoned parent")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if value, err := NewNFSInputLeaseQEMU(canceled, inputs, candidate); value != nil || !errors.Is(err, context.Canceled) || inputs.Check(ctx) != nil {
		return errors.New("pre-canceled reservation affected parent")
	}
	lease, err := NewNFSInputLeaseQEMU(ctx, inputs, candidate)
	if err != nil {
		return err
	}
	nfsInputLeaseProbeRetainedQEMU = lease // ORIGINAL survives any later refusal.
	copyLease := *lease
	if copyLease.Check(ctx) != ErrInvalid || copyLease.Close() != ErrInvalid {
		return errors.New("copied lease accepted")
	}
	if !errors.Is(lease.Check(canceled), context.Canceled) || lease.Check(ctx) != nil || inputs.Check(ctx) != nil {
		return errors.New("pre-canceled check affected lease")
	}
	if value, err := NewNFSInputLeaseQEMU(ctx, inputs, candidate); value != nil || !errors.Is(err, processowner.ErrBusy) {
		return errors.New("second reservation admitted")
	}
	if !errors.Is(inputs.Close(), processowner.ErrBusy) || lease.Check(ctx) != nil || inputs.Check(ctx) != nil {
		return errors.New("parent close consumed reserved inputs")
	}
	if lease.Close() != nil || lease.Close() != nil || lease.Check(ctx) != ErrUnavailable || inputs.Check(ctx) != nil {
		return errors.New("unstarted reservation release failed")
	}
	// A NEW reservation may be prepared after explicit release. This is not a
	// daemon/kernel retry and cannot restore an uncertain/review reservation.
	next, err := NewNFSInputLeaseQEMU(ctx, inputs, candidate)
	if err == nil {
		nfsInputLeaseProbeRetainedQEMU = next
	}
	if err != nil || next == lease || next.Check(ctx) != nil || next.Close() != nil {
		return errors.New("clean released reservation prevented fresh preparation")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("input reservation changed descriptor balance")
	}
	nfsInputLeaseProbeRetainedQEMU = nil // Both unstarted releases were verified.
	return nil
}

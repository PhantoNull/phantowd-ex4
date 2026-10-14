//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

// PreparePlannedDataInputsQEMU prepares ONE fixed disposable two-share process
// tuple from the SAME paired candidate as both retained configuration roles.
// Only independent O_PATH copies are passed to the existing native-data ABI;
// workers keep management lookup and all seven original state objects.
// The trusted caller must freshly compile evidence and verify/retain its exact
// share pins and identity lease OUTSIDE the runtime gate through verified Close.
// No authority callback is invoked here, avoiding runtime -> storage/identity
// lock inversion. Supplied descriptors are inputs, not launch authorization.
// Presence of the inert role still blocks every existing daemon-start API.
// This neither starts a process nor qualifies the future complete coordinator.
func (r *NativeSambaRuntimeQEMU) PreparePlannedDataInputsQEMU(ctx context.Context, candidate fileserviceplan.SambaRoleCandidate, inputs []mountowner.ServiceShareDescriptorQEMU) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonAttempted || r.clientsAttempted || r.plannedDataPrepared {
		return ErrReviewRequired
	}
	if sambaCodeFixtureGuard() != nil || r.owner.configuration == nil || r.owner.serviceConfiguration == nil {
		return ErrInvalid
	}
	management, service, err := plannedConfigurationPlansQEMU(candidate)
	if err != nil {
		return err
	}
	if !matchesConfigurationPlanQEMU(r.owner.configuration, management) || !matchesConfigurationPlanQEMU(r.owner.serviceConfiguration, service) {
		return ErrMismatch
	}
	isolated, err := candidate.ServiceCandidate()
	if err != nil {
		return ErrInvalid
	}
	_, _, _, _, required, err := isolated.Documents()
	if err != nil || len(required) != 2 || len(inputs) != 2 {
		return ErrInvalid
	}
	// This experiment reuses the already-qualified fixed readonly/writable ABI,
	// not arbitrary paths, a recursive handoff root or a generalized ExtraFiles.
	var roots [2]*os.File
	var declarations [2]bool
	for _, request := range required {
		index, ok := plannedDataRoleQEMU(request.ID, request.ReadOnly)
		if !ok || declarations[index] {
			return ErrInvalid
		}
		declarations[index] = true
	}
	for _, input := range inputs {
		index, ok := plannedDataRoleQEMU(input.ShareID, input.ReadOnly)
		if !ok || input.File == nil || roots[index] != nil {
			return ErrInvalid
		}
		roots[index] = input.File
	}
	if roots[0] == roots[1] {
		return ErrInvalid
	}
	if err := r.prepareNativeDaemonQEMU(ctx, &roots); err != nil {
		r.owner.review = true // An uncertain replacement never admits a retry.
		return err
	}
	if err := r.owner.revalidate(ctx); err != nil {
		r.owner.review = true // Keep every original/config/process input retained.
		return ErrReviewRequired
	}
	r.plannedDataPrepared = true
	return nil
}

func plannedDataRoleQEMU(id string, readOnly bool) (int, bool) {
	switch {
	case id == "readonly" && readOnly:
		return 0, true
	case id == "writable" && !readOnly:
		return 1, true
	default:
		return 0, false
	}
}

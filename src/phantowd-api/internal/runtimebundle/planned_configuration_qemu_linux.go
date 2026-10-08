//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"maps"
	"os"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// RetainPlannedConfigurationQEMU adds ONE inert, separately protected daemon
// configuration role to the same runtime. It never changes management lookup,
// the native backend or passdb/state. Presence blocks daemon startup until a
// future complete grant-bound constructor exists. This is test-only retention,
// not storage/identity freshness, installation or service admission authority.
// Complete management expectations must match the existing retained original
// roster from the SAME paired candidate before any service pins are acquired.
// Callers retain their original mounted grants outside the runtime/identity
// gates; no storage or identity callbacks are invoked from this operation.
func (r *NativeSambaRuntimeQEMU) RetainPlannedConfigurationQEMU(ctx context.Context, configuration *os.File, candidate fileserviceplan.SambaRoleCandidate) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil || r.daemonAttempted || r.clientsAttempted || r.owner.serviceConfiguration != nil {
		return ErrReviewRequired
	}
	if configuration == nil || sambaCodeFixtureGuard() != nil || r.owner.configuration == nil || r.owner.configuration.contents == nil {
		return ErrInvalid
	}
	// Expectation comes from the opaque candidate, never staged bytes or a
	// caller-supplied map/hash. Mutable passdb/state are not part of this roster.
	management, expected, err := plannedConfigurationPlansQEMU(candidate)
	if err != nil {
		return err
	}
	if !matchesConfigurationPlanQEMU(r.owner.configuration, management) {
		return ErrMismatch // No new pins or mutation on mismatched management.
	}
	original, err := r.owner.configuration.contents.root.Stat()
	actual, actualErr := configuration.Stat()
	if err != nil || actualErr != nil || os.SameFile(original, actual) {
		return ErrMismatch
	}
	retained, err := expected.retain(ctx, configuration)
	if err != nil {
		return err // Failed construction owns its partial cleanup; caller survives.
	}
	r.owner.serviceConfiguration = retained
	// Complete late fence includes original management/code/state and the new
	// role. Late uncertainty retains every role in review until verified Close.
	if err := r.owner.revalidate(ctx); err != nil {
		r.owner.review = true
		return ErrReviewRequired
	}
	return nil
}

// Only independently rendered opaque candidate output becomes an expectation.
// This pure helper publishes neither descriptor nor filesystem authority.
func plannedConfigurationPlansQEMU(candidate fileserviceplan.SambaRoleCandidate) (*configurationPlan, *configurationPlan, error) {
	management, service, err := SambaRoleDocumentsQEMU(candidate)
	if err != nil {
		return nil, nil, err
	}
	planFor := func(documents map[string]string) (*configurationPlan, error) {
		files := make([]File, 0, len(documents))
		for name, contents := range documents {
			mode := uint32(0644)
			if name == "samba/smb.conf" {
				mode = 0600
			}
			files = append(files, File{Path: name, Size: int64(len(contents)), Mode: mode, SHA256: sha256.Sum256([]byte(contents))})
		}
		return newConfigurationPlan(files)
	}
	m, err := planFor(management)
	if err != nil {
		return nil, nil, err
	}
	s, err := planFor(service)
	if err != nil {
		return nil, nil, err
	}
	return m, s, nil
}

// Equality of expectations is not a freshness scan. The caller must retain the
// normal complete late revalidation of all original code/configuration/state.
func matchesConfigurationPlanQEMU(actual *retainedConfiguration, expected *configurationPlan) bool {
	if actual == nil || actual.contents == nil || actual.contents.plan == nil || expected == nil || expected.plan == nil {
		return false
	}
	a, e := actual.contents.plan, expected.plan
	return len(a.files) == 7 && len(e.files) == 7 && len(a.aliases) == 0 && len(e.aliases) == 0 &&
		a.bytes == e.bytes && slices.Equal(a.files, e.files) && maps.Equal(a.nodes, e.nodes)
}

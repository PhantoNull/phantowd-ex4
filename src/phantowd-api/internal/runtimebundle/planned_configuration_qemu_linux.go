//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// RetainPlannedConfigurationQEMU adds ONE inert, separately protected daemon
// configuration role to the same runtime. It never changes management lookup,
// the native backend or passdb/state. Presence blocks daemon startup until a
// future complete grant-bound constructor exists. This is test-only retention,
// not storage/identity freshness, installation or service admission authority.
// Callers retain their original mounted grants outside the runtime/identity
// gates; no storage or identity callbacks are invoked from this operation.
func (r *NativeSambaRuntimeQEMU) RetainPlannedConfigurationQEMU(ctx context.Context, configuration *os.File, candidate fileserviceplan.SambaIsolatedCandidate) error {
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
	documents, err := SambaPlannedDataDocumentsQEMU(candidate)
	if err != nil {
		return err
	}
	original, err := r.owner.configuration.contents.root.Stat()
	actual, actualErr := configuration.Stat()
	if err != nil || actualErr != nil || os.SameFile(original, actual) {
		return ErrMismatch
	}
	files := make([]File, 0, len(documents))
	for name, contents := range documents {
		mode := uint32(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		files = append(files, File{Path: name, Size: int64(len(contents)), Mode: mode, SHA256: sha256.Sum256([]byte(contents))})
	}
	expected, err := newConfigurationPlan(files)
	if err != nil {
		return err
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

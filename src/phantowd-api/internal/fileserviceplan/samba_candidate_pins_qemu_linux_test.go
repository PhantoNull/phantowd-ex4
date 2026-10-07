//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestIsolatedCandidateCannotReplaceMissingStorageAuthority(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.SambaIsolatedCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(candidate.VerifySharePinsQEMU(nil), ErrNotReady) ||
		!errors.Is((SambaIsolatedCandidate{}).VerifySharePinsQEMU(&mountowner.ServiceSharePinsQEMU{}), ErrNotReady) ||
		!errors.Is(candidate.VerifySharePinsQEMU(&mountowner.ServiceSharePinsQEMU{}), mountowner.ErrHandoffInvalid) {
		t.Fatal("complete candidate manufactured live storage authority")
	}
}

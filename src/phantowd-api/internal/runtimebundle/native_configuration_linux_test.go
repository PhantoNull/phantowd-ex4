//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

func TestNativeConfigurationCannotInventLookupFromZeroCandidate(t *testing.T) {
	plan, err := nativeLookupConfiguration(fileserviceplan.SambaEnrollmentLookup{})
	if plan != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("untrusted empty candidate became protected configuration", err)
	}
}

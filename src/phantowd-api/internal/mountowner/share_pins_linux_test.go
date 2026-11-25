// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"errors"
	"testing"
)

func TestCopiedSharePinsCannotReleaseOriginalReservation(t *testing.T) {
	handoff := &ServiceHandoff{isolatedPins: 1, state: ServiceHandoffActive}
	original := &ServiceSharePins{handoff: handoff}
	original.original = original
	// Reproduce a copied reference without copying the mutex itself.
	copied := &ServiceSharePins{original: original, handoff: handoff, roots: original.roots}
	if !errors.Is(copied.Close(), ErrHandoffInvalid) || !errors.Is(copied.Verify(), ErrHandoffInvalid) ||
		!errors.Is(handoff.Close(), ErrHandoffBusy) {
		t.Fatal("copied pins changed the original handoff")
	}
	if copies, err := copied.DuplicateRoots(); copies != nil || !errors.Is(err, ErrHandoffInvalid) {
		t.Fatal("copied pins issued original descriptors")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
}

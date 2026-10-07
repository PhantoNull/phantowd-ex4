//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestServiceSharePinsRequireOriginalQEMUHandoff(t *testing.T) {
	for _, handoff := range []*ServiceHandoff{nil, {}} {
		pin, err := handoff.RetainShareRootsQEMU()
		if pin != nil || !errors.Is(err, ErrHandoffInvalid) {
			t.Fatal("missing/disposable-guest authority returned share inputs")
		}
	}
	var pin *ServiceSharePinsQEMU
	if _, err := pin.DuplicateRoots(); !errors.Is(err, ErrHandoffInvalid) {
		t.Fatal("absent pin returned data descriptors")
	}
	if err := pin.Verify(); !errors.Is(err, ErrHandoffInvalid) {
		t.Fatal("absent pin verified")
	}
	if err := pin.Close(); !errors.Is(err, ErrHandoffInvalid) {
		t.Fatal("absent pin claimed teardown settlement")
	}
	for _, authority := range []any{&ServiceSharePinsQEMU{}, ServiceSharePinsQEMU{}, ServiceShareDescriptorQEMU{}} {
		if _, err := json.Marshal(authority); err == nil {
			t.Fatal("retained share authority or descriptor serialized")
		}
	}
	var decoded ServiceSharePinsQEMU
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil {
		t.Fatal("retained share authority fabricated by JSON")
	}
	var descriptor ServiceShareDescriptorQEMU
	if err := json.Unmarshal([]byte(`{}`), &descriptor); err == nil {
		t.Fatal("share descriptor fabricated by JSON")
	}
}

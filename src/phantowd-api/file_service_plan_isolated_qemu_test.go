//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestQEMUIsolatedFileServicePlanCandidate(t *testing.T) {
	plan, err := buildQEMUFileServicePlan(qemuPlannerVolumeID, syntheticQEMUStorageSnapshot(qemuPlannerVolumeID, 12))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQEMUIsolatedSambaPlan(plan); err != nil {
		t.Fatal(err)
	}
}

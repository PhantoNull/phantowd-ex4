//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"strings"
)

func runQEMUMountedFileServicePlanFixture() error {
	return errors.New("mounted file-service planning requires the Linux ARMv5 QEMU guest")
}

// Host contract tests cannot run the Linux mount-owner fixture. Keep their
// parser/UI contract isolated from live mount behavior using synthetic storage.
func exerciseQEMUFileServicePlan() error {
	plan, err := buildQEMUFileServicePlan(qemuPlannerVolumeID, syntheticQEMUStorageSnapshot(qemuPlannerVolumeID, 12))
	if err != nil {
		return err
	}
	samba, exports := plan.RenderedCandidates()
	current := plan.Freshness()
	staleGeneration := current
	staleGeneration.StorageGeneration++
	staleFingerprint := current
	staleFingerprint.StorageFingerprint[0] ^= 1
	if !strings.Contains(samba, "write list = alice") || !strings.Contains(exports, "anonuid=1000,anongid=1000") ||
		!plan.FreshAgainst(current) || plan.FreshAgainst(staleGeneration) || plan.FreshAgainst(staleFingerprint) {
		return errors.New("host QEMU file-service plan lost rendering or stale-snapshot protections")
	}
	if _, err := json.Marshal(plan); err == nil {
		return errors.New("QEMU file-service internal plan became serializable")
	}
	return validateQEMUPlanSambaWithTestparm(samba, string(qemuPlannerVolumeID))
}

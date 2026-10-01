//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func exerciseQEMUFileServicePlan() error {
	return mountowner.WithQEMUMountedSetEvidence(smbFixtureAnchor, func(evidence mountowner.MountedVolumeSetEvidence) error {
		observed := evidence.Volumes()
		if !evidence.Complete() || evidence.Generation() == 0 || len(observed) != 1 {
			return errors.New("QEMU mount owner did not return its complete fixed roster")
		}
		mounted := observed[0]
		if mounted.VolumeID() != string(qemuPlannerVolumeID) || mounted.FilesystemUUID() != qemuNFSVolumeUUID ||
			mounted.MountPath() != "/srv/phantowd/volumes/"+string(qemuPlannerVolumeID) ||
			mounted.Compatibility() != fileserviceplan.CompatibilityQualified || mounted.Generation() == 0 ||
			mounted.MountID() == 0 || mounted.DeviceMajor() == 0 || mounted.ReadOnly() {
			return errors.New("QEMU mount owner evidence did not match the fixed planner volume")
		}
		storage, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
		if err != nil || !storage.Complete || storage.Generation != evidence.Generation() ||
			storage.OwnerFingerprint != evidence.Fingerprint() || len(storage.Volumes) != 1 {
			return errors.New("QEMU mounted-owner evidence was not adapted as a complete storage snapshot")
		}
		plan, err := buildQEMUFileServicePlan(qemuPlannerVolumeID, storage)
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
			return errors.New("QEMU file-service plan lost rendering or stale-snapshot protections")
		}
		if _, err := json.Marshal(plan); err == nil {
			return errors.New("QEMU file-service internal plan became serializable")
		}
		return validateQEMUPlanSambaWithTestparm(samba, string(qemuPlannerVolumeID))
	})
}

func runQEMUMountedFileServicePlanFixture() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if err := exerciseQEMUFileServicePlan(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_FILE_SERVICE_PLAN_READY snapshot=complete-mounted-owner-set-nonempty owner_scope=fixture_complete volume_count=1 revisions=bound fresh_check=passed parser=testparm json=false activation=false compatibility=synthetic-ext2 scope=disposable-qemu-only")
	return nil
}

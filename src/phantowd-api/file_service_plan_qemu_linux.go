//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func exerciseQEMUFileServicePlan() error {
	return mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) error {
		lease, evidence, err := set.Acquire(context.Background())
		if err != nil || lease == nil {
			return errors.New("QEMU mounted-volume roster did not issue a complete group lease")
		}
		opened, err := lease.OpenDirectory(string(qemuPlannerVolumeID), ".")
		if err != nil {
			_ = lease.Close()
			return errors.New("QEMU group lease did not open its qualified volume")
		}
		if err := lease.Close(); err != nil {
			return errors.New("QEMU group lease could not release every member")
		}
		if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.New("QEMU group lease did not revoke its tracked directory descriptor")
		}
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
		if err := validateQEMUPlanSambaWithTestparm(samba, string(qemuPlannerVolumeID)); err != nil {
			return err
		}
		if err := validateQEMUIsolatedSambaPlan(plan); err != nil {
			return err
		}
		return exerciseQEMUSambaShareHandoff(plan, storage, set, mounted.MountPath())
	})
}

func exerciseQEMUSambaShareHandoff(plan fileserviceplan.Plan, storage fileserviceplan.StorageSnapshot,
	set *mountowner.MountedVolumeSet, volume string) error {
	const parent = "/run/phantowd/service-handoff"
	const root = parent + "/samba-plan-fixture"
	ctx := context.Background()
	candidate, err := plan.SambaIsolatedCandidate()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0710); err != nil {
		return err
	}
	if err := errors.Join(os.Chown(root, 0, 1000), os.Chmod(root, 0710)); err != nil {
		return err
	}
	storage.Generation++
	stalePlan, err := buildQEMUFileServicePlan(qemuPlannerVolumeID, storage)
	if err != nil {
		return err
	}
	stale, err := stalePlan.SambaIsolatedCandidate()
	if err != nil {
		return err
	}
	if handoff, pins, err := stale.MountShareRoots(ctx, root, set, 1000); handoff != nil || pins != nil || !errors.Is(err, fileserviceplan.ErrNotReady) {
		return errors.New("stale Samba candidate reached share admission")
	}
	handoff, pins, err := candidate.MountShareRoots(ctx, root, set, 1000)
	if err != nil {
		return err
	}
	if err := candidate.VerifyShareRoots(set, pins); err != nil {
		return err
	}
	if err := candidate.VerifyShareRoots(&mountowner.MountedVolumeSet{}, pins); !errors.Is(err, mountowner.ErrHandoffInvalid) {
		return errors.New("Samba share accepted a different mount roster")
	}
	if err := handoff.Close(); !errors.Is(err, mountowner.ErrHandoffBusy) {
		return errors.New("retained Samba share descriptor did not hold its handoff")
	}
	roots, err := pins.DuplicateRoots()
	if err != nil || len(roots) != 1 || roots[0].ShareID != "books" || roots[0].ReadOnly {
		return errors.Join(errors.New("Samba share descriptor did not match its policy"), err)
	}
	original, origErr := os.Stat(filepath.Join(volume, "books"))
	descriptor, statErr := roots[0].File.Stat()
	if err := errors.Join(origErr, statErr, roots[0].File.Close()); err != nil {
		return err
	}
	if !os.SameFile(original, descriptor) {
		return errors.New("Samba share descriptor did not retain the original directory")
	}
	if err := pins.Close(); err != nil {
		return err
	}
	if err := handoff.Close(); err != nil {
		return err
	}
	if err := os.Remove(root); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SAMBA_SHARE_HANDOFF_READY policy=declared original=true stale=refused foreign=refused close_order=verified")
	return nil
}

func runQEMUMountedFileServicePlanFixture() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if err := exerciseQEMUFileServicePlan(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_FILE_SERVICE_PLAN_READY snapshot=complete-mounted-owner-set-nonempty roster_lease=all_member_owned descriptor_revoked=true owner_scope=fixture_complete volume_count=1 revisions=bound fresh_check=passed parser=testparm isolated_candidate=true declared_root=bound json=false activation=false compatibility=synthetic-ext2 scope=disposable-qemu-only")
	return nil
}

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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// Called only inside the existing guarded VersatilePB/disposable MD fixture.
// Registry writes are test-only under fresh tmpfs scratch, never product state.
func exerciseQEMUVolumeRegistry(census trustedMountedExtCensus) error {
	dir, err := os.MkdirTemp("/run", "phantowd-registry-fixture-")
	if err != nil {
		return errors.New("registry tmpfs fixture unavailable")
	}
	defer os.RemoveAll(dir)
	var filesystem unix.Statfs_t
	if unix.Statfs(dir, &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC {
		return errors.New("registry fixture is not disposable tmpfs")
	}
	d := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: 1, Volumes: []shareconfig.Volume{{ID: "logical-registered-md", FilesystemUUID: qemuMDFilesystemUUID},
			{ID: "logical-missing", FilesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb"}}}
	data, err := json.Marshal(d)
	file := filepath.Join(dir, "volumes.json")
	if err != nil || os.WriteFile(file, data, 0600) != nil {
		return errors.New("registry fixture provision failed")
	}
	f, err := os.Open(dir)
	if err != nil {
		return errors.New("registry fixture descriptor unavailable")
	}
	defer f.Close()
	r, err := volumeregistry.Open(f)
	if err != nil {
		return errors.New("protected registry reader unavailable")
	}
	defer r.Close()
	if f.Close() != nil {
		return errors.New("registry borrowed descriptor close failed")
	}
	snapshot, err := r.Read(context.Background())
	if err != nil {
		return errors.New("protected registry observation failed")
	}
	review, err := reviewRegisteredMountedVolumes(snapshot, census)
	if err != nil || review.registryRevision != 1 || review.coverage != census.coverage || len(review.volumes) != 2 ||
		review.volumes[0].volumeID != "logical-missing" || review.volumes[0].status != "not-observed-in-scope" ||
		review.volumes[0].objectCount != 0 || review.volumes[1].volumeID != "logical-registered-md" ||
		review.volumes[1].status != "observed-in-scope" || review.volumes[1].objectCount != 1 ||
		review.volumes[1].aliasCount != 1 || review.volumes[1].scopedDiskEvidenceUnresolved {
		return errors.New("registry reconciliation promoted missing or lost actual MD identity")
	}
	if _, err := json.Marshal(snapshot); err == nil {
		return errors.New("protected registry snapshot serialized")
	}
	if err := r.Recheck(context.Background(), snapshot); err != nil {
		return errors.New("unchanged protected registry recheck failed")
	}
	if _, err := json.Marshal(review); err == nil {
		return errors.New("private registry review serialized")
	}
	backing, err := reviewRegisteredBacking(snapshot, census)
	if err != nil || backing.registryRevision != 1 || backing.coverage != census.coverage || len(backing.volumes) != 2 ||
		backing.volumes[0].observed.volumeID != "logical-missing" || backing.volumes[0].kind != "" ||
		backing.volumes[0].physicalDiskCount != 0 || backing.volumes[0].mdArrayCount != 0 ||
		backing.volumes[1].observed.volumeID != "logical-registered-md" || backing.volumes[1].kind != "md-device" ||
		backing.volumes[1].physicalDiskCount != 2 || backing.volumes[1].mdArrayCount != 1 ||
		backing.volumes[1].observed.scopedDiskEvidenceUnresolved {
		return errors.New("registry backing topology lost actual MD or selected missing claim")
	}
	if _, err := json.Marshal(backing); err == nil {
		return errors.New("private registry backing observation serialized")
	}
	fmt.Println("PHANTOWD_REGISTRY_BACKING_READY actual_md_device=true physical_disks=2 arrays=1 missing_unselected=true private=true identity_qualification=false activation=false scope=disposable-qemu-only")
	policy := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 7,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 7,
			Volumes: append([]shareconfig.Volume{}, d.Volumes...), Users: []shareconfig.User{{ID: "reader", Name: "reader"}},
			Shares: []shareconfig.Share{{ID: "books-share", Name: "Books", VolumeID: "logical-registered-md", RelativePath: "books",
				Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 7, VolumeRevision: 7,
			Exports: []nfsconfig.Export{{ID: "11111111-2222-3333-4444-555555555555", VolumeID: "logical-registered-md", RelativePath: "audio",
				Clients: []nfsconfig.Client{{Network: "192.0.2.0/24", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}}}
	bound, err := reviewRegisteredPolicyVolumes(policy, snapshot, census)
	if err != nil || bound.policyRevision != 7 || bound.registryRevision != 1 || len(bound.volumes) != 2 ||
		bound.volumes[1].observed.volumeID != "logical-registered-md" || bound.volumes[1].observed.status != "observed-in-scope" ||
		bound.volumes[1].smbShareCount != 1 || bound.volumes[1].nfsExportCount != 1 ||
		bound.volumes[0].observed.status != "not-observed-in-scope" || bound.unreferencedRegisteredCount != 0 {
		return errors.New("combined policy lost protected registry binding or protocol references")
	}
	if _, err := json.Marshal(bound); err == nil {
		return errors.New("private combined registry review serialized")
	}
	composed, err := collectRegisteredStorageReview(context.Background(), policy, r, os.DirFS("/sys"), os.DirFS("/proc"))
	if err != nil || composed.policy.policyRevision != 7 || composed.policy.registryRevision != 1 ||
		composed.backing.registryRevision != 1 || composed.policy.coverage != composed.backing.coverage ||
		len(composed.policy.volumes) != 2 || len(composed.backing.volumes) != 2 ||
		composed.policy.volumes[1].smbShareCount != 1 || composed.policy.volumes[1].nfsExportCount != 1 ||
		composed.backing.volumes[1].kind != "md-device" || composed.backing.volumes[1].physicalDiskCount != 2 ||
		composed.backing.volumes[0].kind != "" {
		return errors.New("composed registry and actual complete census review failed")
	}
	if _, err := json.Marshal(composed); err == nil {
		return errors.New("composed registry and census review serialized")
	}
	observations := 0
	changed, err := collectRegisteredStorageReviewWith(context.Background(), policy, r, os.DirFS("/sys"), os.DirFS("/proc"),
		func(anchors []string) (mountguard.MountedInventory, error) {
			observations++
			if observations == 3 {
				// Restore only the existing tmpfs fixture while the second complete
				// census is being checked. The reader must retain that mutation.
				if os.WriteFile(file, []byte("{}"), 0600) != nil || os.WriteFile(file, data, 0600) != nil {
					return mountguard.MountedInventory{}, volumeregistry.ErrObservation
				}
			}
			return mountguard.ObserveMounted(anchors)
		})
	if err != volumeregistry.ErrObservation || observations != 4 || changed.policy.volumes != nil || changed.backing.volumes != nil {
		return errors.New("registry restoration during full census published a partial review")
	}
	fmt.Println("PHANTOWD_REGISTRY_CENSUS_READY complete_scope=true revisions_separate=true restored_registry_refused=true private=true continued_freshness=false activation=false scope=disposable-qemu-only")
	// Valid desired policies cannot reassign a registry ID or infer one by UUID.
	policy.Shares.Volumes[0].FilesystemUUID = "88888888-9999-aaaa-bbbb-cccccccccccc"
	conflict, err := reviewRegisteredPolicyVolumes(policy, snapshot, census)
	if err != nil || conflict.volumes[1].observed.status != "registry-policy-conflict" || conflict.volumes[1].observed.objectCount != 0 {
		return errors.New("different policy backing silently overwrote registry claim")
	}
	policy.Shares.Volumes[0].FilesystemUUID = qemuMDFilesystemUUID
	policy.Shares.Volumes[0].ID = "unregistered-same-uuid"
	policy.Shares.Shares[0].VolumeID = "unregistered-same-uuid"
	policy.NFS.Exports[0].VolumeID = "unregistered-same-uuid"
	unknown, err := reviewRegisteredPolicyVolumes(policy, snapshot, census)
	if err != nil || unknown.volumes[1].observed.status != "not-registered" || unknown.volumes[1].observed.objectCount != 0 || unknown.unreferencedRegisteredCount != 1 {
		return errors.New("UUID alone selected a different logical registration")
	}
	policy.NFS.Revision++
	if _, err := reviewRegisteredPolicyVolumes(policy, snapshot, census); err != volumeregistry.ErrObservation {
		return errors.New("split combined policy produced a registry observation")
	}
	fmt.Println("PHANTOWD_REGISTRY_POLICY_READY revisions_separate=true logical_binding_exact=true unknown_id_refused=true uuid_conflict=true split_policy_refused=true smb_refs=1 nfs_refs=1 activation=false scope=disposable-qemu-only")
	if os.Chmod(file, 0644) != nil {
		return errors.New("registry unsafe-mode fixture failed")
	}
	if _, err := r.Read(context.Background()); !errors.Is(err, volumeregistry.ErrObservation) {
		return errors.New("unsafe registry mode accepted")
	}
	if os.Chmod(file, 0600) != nil {
		return errors.New("registry fixture mode restore failed")
	}
	if _, err := r.Read(context.Background()); err != nil {
		return errors.New("restored private fixture could not be observed")
	}
	if r.Recheck(context.Background(), snapshot) != volumeregistry.ErrObservation {
		return errors.New("restored registry permissions rehabilitated an old snapshot")
	}
	fresh, err := r.Read(context.Background())
	if err != nil || r.Recheck(context.Background(), fresh) != nil {
		return errors.New("fresh explicit registry observation recheck failed")
	}
	// Fast rewrite/restore can preserve timestamps; the retained kernel watch
	// must still invalidate the earlier read. Only fresh fixture tmpfs is written.
	if os.WriteFile(file, []byte("{}"), 0600) != nil || os.WriteFile(file, data, 0600) != nil ||
		r.Recheck(context.Background(), fresh) != volumeregistry.ErrObservation {
		return errors.New("registry same-byte restore escaped change history")
	}
	fmt.Println("PHANTOWD_REGISTRY_RECHECK_READY same_reader=true stable=true restored_old_refused=true same_bytes_restore_refused=true private=true continued_freshness=false activation=false scope=disposable-qemu-only")
	if os.Chown(file, 12345, -1) != nil {
		return errors.New("registry foreign-owner fixture failed")
	}
	if _, err := r.Read(context.Background()); err != volumeregistry.ErrObservation {
		return errors.New("foreign registry owner accepted")
	}
	if os.Chown(file, os.Geteuid(), -1) != nil {
		return errors.New("registry fixture owner restore failed")
	}
	if _, err := r.Read(context.Background()); err != nil {
		return errors.New("restored registry fixture owner refused")
	}
	return nil
}

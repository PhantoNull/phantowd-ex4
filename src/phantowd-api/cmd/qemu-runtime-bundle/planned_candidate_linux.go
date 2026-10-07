//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const plannedCandidateMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY owner=actual_native_backend storage=mounted_roster locked_plan=true exact_declaration=true original_objects=true caller_close=true fresh_recompiled=true identity_retained=true handoff_close_gated=true desired_roundtrip=true journals_unchanged=true stale_refused=true released=true samba_data=false activation=false scope=qemu-only"

// Runs after real enrollment, before ANY lifecycle daemon starts. It retains
// the SAME Owner/backend and actual mounted roster through descriptor closure.
// This positive Plan/candidate/handoff admission proof does not start Samba or
// substitute for the full planned native-service coordinator.
func nativePlannedCandidateFixtureQEMU(owner *identityowner.Owner, backend *smbexec.NativeBackendQEMU) error {
	if owner == nil || backend == nil {
		return errors.New("planned candidate requires actual native authorities")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return mountowner.WithQEMUNativeMountedSet(func(storage *mountowner.MountedVolumeSet) error {
		before, err := owner.FileServiceSnapshot(ctx)
		if err != nil || len(before.Registry.Accounts) != 2 || len(before.Passdb) != 2 ||
			before.Registry.Accounts[1].Name != "qpsecond" || before.Registry.Accounts[1].State != serviceaccounts.Disabled {
			return errors.New("planned candidate initial native evidence")
		}
		peer := before.Registry.Accounts[1]
		if err := owner.SetDesiredState(ctx, before.Registry.Revision, peer.ID, serviceaccounts.Enabled); err != nil {
			return err
		}
		const source = "/run/phantowd-samba-source"
		const root = "/run/phantowd/service-handoff/native-candidate"
		for _, name := range []string{"candidate-readonly", "candidate-writable"} {
			path := source + "/" + name
			if err := os.Mkdir(path, 0770); err != nil {
				return err
			}
			if err := errors.Join(os.Chown(path, int(peer.UID), int(peer.GID)), os.Chmod(path, 0770)); err != nil {
				return err
			}
		}
		config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: mountowner.QEMUNativeVolumeID, FilesystemUUID: mountowner.QEMUNativeFilesystemUUID}},
				Users:   []shareconfig.User{{ID: peer.ID, Name: peer.Name}}, Shares: []shareconfig.Share{
					{ID: "readonly", Name: "ReadOnly", VolumeID: mountowner.QEMUNativeVolumeID, RelativePath: "candidate-readonly", Grants: []shareconfig.Grant{{UserID: peer.ID, Access: "ro"}}},
					{ID: "writable", Name: "Writable", VolumeID: mountowner.QEMUNativeVolumeID, RelativePath: "candidate-writable", Grants: []shareconfig.Grant{{UserID: peer.ID, Access: "rw"}}},
				}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}},
		}
		plan, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage)
		if err != nil {
			return err
		}
		candidate, err := plan.SambaIsolatedCandidate()
		if err != nil {
			return err
		}
		_, _, _, _, requests, err := candidate.Documents()
		if err != nil || len(requests) != 2 {
			return errors.New("planned candidate incomplete documents")
		}
		consumer, err := owner.RetainSMBFileServiceSnapshot(ctx, plan.Freshness().IdentityFingerprint, backend)
		if err != nil {
			return err
		}
		// Late uncertainty deliberately retains authorities until this disposable
		// guest exits. No defer retries cleanup or releases a possibly live pin.
		if !errors.Is(owner.Close(), identityowner.ErrBusy) {
			return errors.New("planned candidate lost retained identity")
		}
		if err := os.MkdirAll("/run/phantowd/service-handoff", 0755); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0710); err != nil {
			return err
		}
		if err := errors.Join(os.Chown(root, 0, 1000), os.Chmod(root, 0710)); err != nil {
			return err
		}
		shares := make([]mountowner.ServiceShare, len(requests))
		for index, request := range requests {
			shares[index] = mountowner.ServiceShare{ID: request.ID, VolumeID: string(request.VolumeID),
				RelativePath: request.RelativePath, ReadOnly: request.ReadOnly}
		}
		handoff, err := mountowner.NewServiceHandoff(root, storage, shares, 1000)
		if err != nil {
			return err
		}
		if _, err := handoff.Mount(ctx); err != nil {
			return err
		}
		pins, err := handoff.RetainShareRootsQEMU()
		if err != nil {
			return err // Non-nil quarantined handles remain retained in this guest.
		}
		if candidate.VerifySharePinsQEMU(pins) != nil || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
			return errors.New("planned candidate did not bind the SAME retained mounted roots")
		}
		inputs, err := pins.DuplicateRoots()
		if err != nil || len(inputs) != len(requests) {
			return errors.New("planned candidate descriptor census")
		}
		for index, input := range inputs {
			request := requests[index]
			original, err := os.Stat(source + "/" + request.RelativePath)
			actual, actualErr := input.File.Stat()
			var fs unix.Statfs_t
			if err != nil || actualErr != nil || !os.SameFile(original, actual) ||
				input.ShareID != request.ID || input.ReadOnly != request.ReadOnly ||
				unix.Fstatfs(int(input.File.Fd()), &fs) != nil || (fs.Flags&unix.ST_RDONLY != 0) != request.ReadOnly {
				return errors.New("planned candidate descriptor object/role mismatch")
			}
			if err := input.File.Close(); err != nil {
				return err
			}
		}
		fresh, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage)
		if err != nil || !candidate.FreshAgainst(fresh.Freshness()) || candidate.VerifySharePinsQEMU(pins) != nil || consumer.Verify(ctx) != nil {
			return errors.New("planned candidate lost freshly recompiled/retained authority")
		}
		if err := pins.Close(); err != nil {
			return err
		}
		if err := handoff.Close(); err != nil {
			return err
		}
		if err := consumer.Release(); err != nil {
			return err
		}
		current, _, err := owner.Snapshot(ctx)
		if err != nil {
			return err
		}
		if err := owner.SetDesiredState(ctx, current.Revision, peer.ID, serviceaccounts.Disabled); err != nil {
			return err
		}
		after, err := owner.FileServiceSnapshot(ctx)
		if err != nil || after.Registry.Revision != before.Registry.Revision+2 ||
			!slices.Equal(before.Registry.Accounts, after.Registry.Accounts) ||
			!slices.Equal(before.Native, after.Native) || !slices.Equal(before.Samba, after.Samba) || !slices.Equal(before.Passdb, after.Passdb) {
			return errors.New("planned candidate desired roundtrip changed native identities")
		}
		stale := plan.Freshness()
		stale.IdentityGeneration, stale.IdentityFingerprint = after.Registry.Revision, after.Fingerprint
		if candidate.FreshAgainst(stale) {
			return errors.New("planned candidate survived actual identity-generation transition")
		}
		if _, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage); !errors.Is(err, fileserviceplan.ErrNotReady) {
			return errors.New("planned candidate admitted restored disabled desired user")
		}
		for _, path := range []string{root, source + "/candidate-readonly", source + "/candidate-writable"} {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})
}

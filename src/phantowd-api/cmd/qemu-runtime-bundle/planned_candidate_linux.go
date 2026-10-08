//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

const plannedCandidateMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY owner=actual_native_backend storage=mounted_roster locked_plan=true exact_declaration=true original_objects=true caller_close=true fresh_recompiled=true rendered=true granted_only=true paired_lookup=true management_complete=true shared_globals=true management_bound=true protected_role=true management_unchanged=true prepared_inputs=true service_config_bound=true share_inputs_bound=true coordinator_bound=true same_roster=true policy_copy=true startup_blocked=true identity_retained=true handoff_close_gated=true desired_roundtrip=true journals_unchanged=true stale_refused=true runtime_close_before_release=true released=true samba_data=false activation=false scope=qemu-only"

// Runs after real enrollment, before ANY lifecycle daemon starts. It retains
// the SAME Owner/backend and actual mounted roster through descriptor closure.
// This positive Plan/candidate/handoff admission proof does not start Samba or
// substitute for the full planned native-service coordinator.
func nativePlannedCandidateFixtureQEMU(owner *identityowner.Owner, backend *smbexec.NativeBackendQEMU, runtime *runtimebundle.NativeSambaRuntimeQEMU) (*plannedConfigurationStageQEMU, error) {
	if owner == nil || backend == nil || runtime == nil {
		return nil, errors.New("planned candidate requires actual native authorities")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var stage *plannedConfigurationStageQEMU
	err := mountowner.WithQEMUNativeMountedSet(func(storage *mountowner.MountedVolumeSet) error {
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
		roles, err := plan.SambaRoleCandidate()
		if err != nil {
			return err
		}
		passwd, group, nss, sections, requests, err := candidate.Documents()
		if err != nil || len(requests) != 2 {
			return errors.New("planned candidate incomplete documents")
		}
		documents, err := runtimebundle.SambaPlannedDataDocumentsQEMU(candidate)
		if err != nil || len(documents) != 7 || documents["passwd"] != passwd || documents["group"] != group ||
			documents["nsswitch.conf"] != nss || !strings.HasSuffix(documents["samba/smb.conf"], sections) ||
			!strings.Contains(passwd, "qpsecond:!:2001:2001:") || strings.Contains(passwd, "qpmanaged:") ||
			strings.Contains(group, "qpmanaged:") {
			return errors.New("planned rendering lost complete granted-only native documents")
		}
		management, service, err := runtimebundle.SambaRoleDocumentsQEMU(roles)
		if err != nil || !maps.Equal(service, documents) || len(management) != 7 ||
			service["samba/smb.conf"] != management["samba/smb.conf"]+sections {
			return errors.New("paired lookup changed grants or shared global/state paths")
		}
		lookup, err := unixidentity.Parse(strings.NewReader(management["passwd"]), strings.NewReader(management["group"]))
		if err != nil || !unixidentity.FilesOnlyNSS([]byte(management["nsswitch.conf"])) {
			return errors.New("paired management lookup grammar")
		}
		for _, account := range before.Registry.Accounts {
			if status, err := lookup.Assess(account); err != nil || status != unixidentity.Observed {
				return errors.New("paired management lookup omitted actual native identity")
			}
		}
		expectedManagement := maps.Clone(management)
		management["passwd"] = "replacement"
		delete(service, "group")
		if documents["group"] != group {
			return errors.New("paired caller maps alias single-role output")
		}
		// Caller mutation must not change this candidate's later complete output.
		expectedDocuments := maps.Clone(documents)
		documents["passwd"] = "replacement"
		delete(documents, "samba/smb.conf")
		repeated, err := runtimebundle.SambaPlannedDataDocumentsQEMU(candidate)
		if err != nil || !maps.Equal(expectedDocuments, repeated) {
			return errors.New("planned rendering lost caller independence")
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
		fresh, err := fileserviceplan.BuildFromRetainedOwners(ctx, config, 0, consumer, storage)
		if err != nil || !candidate.FreshAgainst(fresh.Freshness()) || !roles.FreshAgainst(fresh.Freshness()) ||
			candidate.VerifySharePinsQEMU(pins) != nil {
			return errors.New("planned candidate lost freshly recompiled/retained authority")
		}
		freshCandidate, err := fresh.SambaIsolatedCandidate()
		if err != nil {
			return err
		}
		freshDocuments, err := runtimebundle.SambaPlannedDataDocumentsQEMU(freshCandidate)
		if err != nil || !maps.Equal(expectedDocuments, freshDocuments) {
			return errors.New("planned native rendering changed after complete evidence recompile")
		}
		freshRoles, err := fresh.SambaRoleCandidate()
		if err != nil {
			return err
		}
		freshManagement, freshService, err := runtimebundle.SambaRoleDocumentsQEMU(freshRoles)
		if err != nil || !maps.Equal(expectedManagement, freshManagement) || !maps.Equal(expectedDocuments, freshService) {
			return errors.New("paired native rendering changed after complete evidence recompile")
		}
		stage, err = stagePlannedConfigurationQEMU(ctx, runtime, freshRoles)
		if err != nil {
			return err
		}
		// The original no-process desired roundtrip remains before any planned
		// process inputs are captured. No live service authority is released.
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
		if candidate.FreshAgainst(stale) || roles.FreshAgainst(stale) {
			return errors.New("planned candidate survived actual identity-generation transition")
		}
		if _, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage); !errors.Is(err, fileserviceplan.ErrNotReady) {
			return errors.New("planned candidate admitted restored disabled desired user")
		}
		if err := owner.SetDesiredState(ctx, after.Registry.Revision, peer.ID, serviceaccounts.Enabled); err != nil {
			return err
		}
		preparedPlan, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage)
		if err != nil {
			return err
		}
		preparedRoles, err := preparedPlan.SambaRoleCandidate()
		if err != nil {
			return err
		}
		preparedCandidate, err := preparedRoles.ServiceCandidate()
		if err != nil || preparedCandidate.VerifySharePinsQEMU(pins) != nil {
			return errors.New("planned input preparation lost exact original grants")
		}
		if !errors.Is(pins.VerifySourceSetQEMU(nil), mountowner.ErrHandoffInvalid) ||
			!errors.Is(pins.VerifySourceSetQEMU(&mountowner.MountedVolumeSet{}), mountowner.ErrHandoffInvalid) ||
			pins.VerifySourceSetQEMU(storage) != nil {
			return errors.New("planned share authority accepted an unrelated roster or changed after refusal")
		}
		preparedInputs, err := pins.DuplicateRoots()
		if err != nil {
			return err
		}
		if len(preparedInputs) != 2 {
			return errors.New("planned original input census")
		}
		for _, invalid := range [][]mountowner.ServiceShareDescriptorQEMU{
			nil, preparedInputs[:1],
			{{ShareID: "foreign", ReadOnly: preparedInputs[0].ReadOnly, File: preparedInputs[0].File}, preparedInputs[1]},
			{{ShareID: preparedInputs[0].ShareID, ReadOnly: !preparedInputs[0].ReadOnly, File: preparedInputs[0].File}, preparedInputs[1]},
			{{ShareID: preparedInputs[0].ShareID, ReadOnly: preparedInputs[0].ReadOnly}, preparedInputs[1]},
			{preparedInputs[0], preparedInputs[0]},
		} {
			if err := runtime.PreparePlannedDataInputsQEMU(ctx, preparedRoles, invalid); !errors.Is(err, runtimebundle.ErrInvalid) {
				return errors.New("planned input declaration refusal missing")
			}
		}
		if err := runtime.PreparePlannedDataInputsQEMU(ctx, fileserviceplan.SambaRoleCandidate{}, preparedInputs); !errors.Is(err, runtimebundle.ErrInvalid) {
			return errors.New("planned input empty candidate admitted")
		}
		canceled, cancelPreparation := context.WithCancel(ctx)
		cancelPreparation()
		if err := runtime.PreparePlannedDataInputsQEMU(canceled, preparedRoles, preparedInputs); !errors.Is(err, context.Canceled) {
			return errors.New("planned input canceled preparation admitted")
		}
		// Transfer only the actual retained share authority, not a caller's
		// descriptor tuple or a previously rendered candidate. The coordinator
		// must compile its own complete evidence and prepare independent copies.
		var prepareErr error
		for _, input := range preparedInputs {
			prepareErr = errors.Join(prepareErr, input.File.Close())
		}
		if prepareErr != nil {
			return fmt.Errorf("planned original caller release: %w", prepareErr)
		}
		serviceOwner, err := smbexec.NewNativePlannedServiceQEMU(ctx, smbexec.NativePlannedInputsQEMU{
			Policy: config, Identity: owner, Storage: storage, Shares: pins, Backend: backend,
		})
		if err != nil {
			return fmt.Errorf("planned same-authority service construction: %w", err)
		}
		status, err := serviceOwner.Status()
		if err != nil || status.State != "prepared" || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed {
			return errors.New("planned service did not retain the complete authority tuple")
		}
		if !errors.Is(runtime.PreparePlannedDataInputsQEMU(ctx, preparedRoles, nil), runtimebundle.ErrReviewRequired) ||
			!errors.Is(runtime.CheckNativeStartupQEMU(ctx), runtimebundle.ErrReviewRequired) ||
			!errors.Is(runtime.StartNativeDaemonQEMU(ctx), runtimebundle.ErrReviewRequired) {
			return errors.New("planned prepared tuple replaced or admitted startup")
		}
		if !errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) ||
			preparedCandidate.VerifySharePinsQEMU(pins) != nil {
			return errors.New("planned process inputs lost retained authorities")
		}
		originalPath := config.Shares.Shares[0].RelativePath
		config.Shares.Shares[0].RelativePath = "caller-replacement"
		if err := serviceOwner.Observe(ctx); err != nil {
			return fmt.Errorf("planned service retained caller policy aliases: %w", err)
		}
		config.Shares.Shares[0].RelativePath = originalPath
		// No daemon is admitted. Release ALL runtime-owned copies before either
		// original storage or identity authority can be released.
		if err := serviceOwner.Close(context.Background()); err != nil {
			return err
		}
		status, err = serviceOwner.Status()
		if err != nil || status.State != "stopped" || status.IdentityRetained || status.SharesRetained || !status.RuntimeClosed {
			return errors.New("planned service released authorities before verified runtime closure")
		}
		if err := pins.Close(); err != nil {
			return err
		}
		if err := handoff.Close(); err != nil {
			return err
		}
		current, _, err = owner.Snapshot(ctx)
		if err != nil {
			return err
		}
		if err := owner.SetDesiredState(ctx, current.Revision, peer.ID, serviceaccounts.Disabled); err != nil {
			return err
		}
		for _, path := range []string{root, source + "/candidate-readonly", source + "/candidate-writable"} {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})
	return stage, err
}

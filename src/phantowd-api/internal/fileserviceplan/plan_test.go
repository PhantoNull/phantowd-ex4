// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	testVolumeUUID = "11111111-2222-3333-4444-555555555555"
	testExportID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testSID        = "S-1-5-21-1-2-3-1001"
)

func planInputs(t *testing.T) (fileservice.Config, uint64, IdentitySnapshot, StorageSnapshot) {
	t.Helper()

	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = registry.Create(registry.Revision, "writer", "alice", serviceaccounts.Reservations{
		UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err = registry.SetState(registry.Revision, "writer", serviceaccounts.Enabled)
	if err != nil {
		t.Fatal(err)
	}
	account := registry.Accounts[0]
	sambaAccount := account
	sambaAccount.State = serviceaccounts.Disabled
	journal := smbprovision.Journal{
		Format: smbprovision.Format, SchemaVersion: 1, Revision: 7,
		NativeRevision: registry.Revision, Account: sambaAccount, SID: testSID, Phase: smbprovision.Enabled,
	}
	observation := smbprovision.Observation{
		Present: true, Name: account.Name, UID: account.UID, GID: account.GID, SID: testSID,
	}

	shares := shareconfig.Config{
		Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 7,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: testVolumeUUID}},
		Users:   []shareconfig.User{{ID: account.ID, Name: account.Name}},
		Shares: []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: "books",
			Grants: []shareconfig.Grant{{UserID: account.ID, Access: "rw"}}}},
	}
	nfs := nfsconfig.Policy{
		Format: nfsconfig.Format, SchemaVersion: 1, Revision: 7, VolumeRevision: 7,
		Exports: []nfsconfig.Export{{ID: testExportID, VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all",
				AnonymousUID: account.UID, AnonymousGID: account.GID, Security: "sys"}}}},
	}
	config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 7, Shares: shares, NFS: nfs}

	identity := IdentitySnapshot{
		Complete: true, Generation: 29, Registry: registry,
		UnixUIDs: []uint32{account.UID},
		UnixGIDs: []uint32{account.GID},
		Samba:    []SambaIdentity{{Journal: journal, Observation: observation}},
	}
	storage := StorageSnapshot{Complete: true, Generation: 41, Volumes: []ObservedVolume{{
		VolumeID: "bulk", FilesystemUUID: testVolumeUUID,
		MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: CompatibilityQualified,
		MountID: 73, DeviceMajor: 9, DeviceMinor: 1,
	}}}
	return config, 5, identity, storage
}

func TestBuildPlanResolvesCombinedPolicyWithoutActivationAuthority(t *testing.T) {
	config, activeRevision, identity, storage := planInputs(t)
	plan, err := Build(config, activeRevision, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	if plan.schemaVersion != 1 || plan.scope != "candidate-only" || plan.activationAvailable || plan.applied || plan.runtimeValidated {
		t.Fatalf("plan overstated its authority: %+v", plan)
	}
	if plan.freshness.PolicyRevision != config.Revision || plan.freshness.ActiveRevision != activeRevision ||
		plan.freshness.IdentityGeneration != identity.Generation || plan.freshness.StorageGeneration != storage.Generation {
		t.Fatalf("plan lost revision bindings: %+v", plan)
	}
	if len(plan.volumes) != 1 || plan.volumes[0].VolumeID != "bulk" ||
		plan.volumes[0].FilesystemUUID != testVolumeUUID || plan.volumes[0].MountID != 73 {
		t.Fatalf("unexpected resolved volume set: %+v", plan.volumes)
	}
	if !strings.Contains(plan.sambaConfig, "write list = alice") ||
		!strings.Contains(plan.nfsConfig, "anonuid=1000,anongid=1000") ||
		!plan.FreshAgainst(Freshness{PolicyRevision: 7, ActiveRevision: 5, IdentityGeneration: 29, StorageGeneration: 41}) {
		t.Fatalf("plan lost service configuration or freshness contract: %+v", plan)
	}
}

func TestBuildPlanRejectsIncompleteSnapshots(t *testing.T) {
	for _, mutate := range []struct {
		name string
		edit func(*fileservice.Config, *uint64, *IdentitySnapshot, *StorageSnapshot)
	}{
		{"identity incomplete", func(_ *fileservice.Config, _ *uint64, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Complete = false
		}},
		{"storage incomplete", func(_ *fileservice.Config, _ *uint64, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Complete = false
		}},
		{"identity generation missing", func(_ *fileservice.Config, _ *uint64, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Generation = 0
		}},
		{"storage generation missing", func(_ *fileservice.Config, _ *uint64, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Generation = 0
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			config, active, identity, storage := planInputs(t)
			mutate.edit(&config, &active, &identity, &storage)
			if _, err := Build(config, active, identity, storage); !errors.Is(err, ErrNotReady) {
				t.Fatalf("expected fail-closed readiness error, got %v", err)
			}
		})
	}
}

func TestBuildPlanRejectsStorageIdentityAndMountConflicts(t *testing.T) {
	for _, mutate := range []struct {
		name string
		want error
		edit func(*fileservice.Config, *IdentitySnapshot, *StorageSnapshot)
	}{
		{"missing volume", ErrNotReady, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes = []ObservedVolume{}
		}},
		{"filesystem UUID mismatch", ErrInvalidEvidence, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes[0].FilesystemUUID = "22222222-2222-3333-4444-555555555555"
		}},
		{"unsafe anchor", ErrInvalidEvidence, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes[0].MountPath = "/srv/phantowd/volumes/bulk/.."
		}},
		{"unknown compatibility", ErrInvalidEvidence, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes[0].Compatibility = "unknown"
		}},
		{"required volume unqualified", ErrNotReady, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes[0].Compatibility = CompatibilityUnqualified
		}},
		{"duplicate filesystem UUID", ErrInvalidEvidence, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes = append(storage.Volumes, ObservedVolume{VolumeID: "archive", FilesystemUUID: testVolumeUUID,
				MountPath: shareconfig.VolumeMountRoot + "/archive", Compatibility: CompatibilityUnqualified,
				MountID: 74, DeviceMajor: 9, DeviceMinor: 2})
		}},
		{"duplicate mount identity", ErrInvalidEvidence, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes = append(storage.Volumes, ObservedVolume{VolumeID: "archive", FilesystemUUID: "22222222-2222-3333-4444-555555555555",
				MountPath: shareconfig.VolumeMountRoot + "/archive", Compatibility: CompatibilityUnqualified,
				MountID: 73, DeviceMajor: 9, DeviceMinor: 2})
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			config, active, identity, storage := planInputs(t)
			mutate.edit(&config, &identity, &storage)
			if _, err := Build(config, active, identity, storage); !errors.Is(err, mutate.want) {
				t.Fatalf("expected storage evidence rejection, got %v", err)
			}
		})
	}
}

func TestPlanIsNotSerializableAndGettersReturnCopies(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(plan); err == nil {
		t.Fatal("internal candidate plan was serializable")
	}
	var decoded Plan
	if err := json.Unmarshal([]byte(`{"schema_version":1,"scope":"candidate-only"}`), &decoded); err == nil {
		t.Fatal("external JSON was accepted as an internal plan")
	}
	volumes := plan.RequiredVolumes()
	volumes[0].FilesystemUUID = "22222222-2222-3333-4444-555555555555"
	if plan.volumes[0].FilesystemUUID != testVolumeUUID {
		t.Fatal("caller mutation changed the plan")
	}
	requirements := plan.Requirements()
	requirements[0] = "caller-controlled"
	if plan.requirements[0] == "caller-controlled" {
		t.Fatal("caller mutation changed plan requirements")
	}
}

func TestBuildPlanRejectsUnreadyOrInconsistentIdentitiesAndReadonlyWrites(t *testing.T) {
	tests := []struct {
		name string
		want error
		edit func(*fileservice.Config, *IdentitySnapshot, *StorageSnapshot)
	}{
		{"account not enabled", ErrNotReady, func(_ *fileservice.Config, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Registry.Accounts[0].State = serviceaccounts.Disabled
		}},
		{"Samba journal inconsistent", ErrInvalidEvidence, func(_ *fileservice.Config, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Samba[0].Journal.Phase = smbprovision.Disabled
		}},
		{"Samba observation disabled", ErrNotReady, func(_ *fileservice.Config, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Samba[0].Observation.Disabled = true
		}},
		{"missing anonymous uid", ErrNotReady, func(_ *fileservice.Config, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.UnixUIDs = []uint32{}
		}},
		{"missing anonymous gid", ErrNotReady, func(_ *fileservice.Config, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.UnixGIDs = []uint32{}
		}},
		{"write request on readonly volume", ErrNotReady, func(_ *fileservice.Config, _ *IdentitySnapshot, storage *StorageSnapshot) {
			storage.Volumes[0].ReadOnly = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, active, identity, storage := planInputs(t)
			test.edit(&config, &identity, &storage)
			if _, err := Build(config, active, identity, storage); !errors.Is(err, test.want) {
				t.Fatalf("expected fail-closed error %v, got %v", test.want, err)
			}
		})
	}
}

func TestPlanFreshnessRejectsEveryChangedRevision(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	base := Freshness{PolicyRevision: 7, ActiveRevision: 5, IdentityGeneration: 29, StorageGeneration: 41}
	for name, stale := range map[string]Freshness{
		"policy":   {PolicyRevision: 8, ActiveRevision: 5, IdentityGeneration: 29, StorageGeneration: 41},
		"active":   {PolicyRevision: 7, ActiveRevision: 6, IdentityGeneration: 29, StorageGeneration: 41},
		"identity": {PolicyRevision: 7, ActiveRevision: 5, IdentityGeneration: 30, StorageGeneration: 41},
		"storage":  {PolicyRevision: 7, ActiveRevision: 5, IdentityGeneration: 29, StorageGeneration: 42},
	} {
		if plan.FreshAgainst(stale) {
			t.Errorf("stale %s snapshot accepted", name)
		}
	}
	if !plan.FreshAgainst(base) {
		t.Fatal("current exact snapshot rejected")
	}
}

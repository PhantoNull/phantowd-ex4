// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
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
		Complete: true, Generation: 29, Fingerprint: sha256.Sum256([]byte("fileserviceplan-test-identity-v1")), Registry: registry,
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
		plan.freshness.IdentityGeneration != identity.Generation || plan.freshness.StorageGeneration != storage.Generation ||
		plan.freshness.StorageFingerprint != fingerprintStorageSnapshot(storage) {
		t.Fatalf("plan lost revision bindings: %+v", plan)
	}
	if len(plan.volumes) != 1 || plan.volumes[0].VolumeID != "bulk" ||
		plan.volumes[0].FilesystemUUID != testVolumeUUID || plan.volumes[0].MountID != 73 {
		t.Fatalf("unexpected resolved volume set: %+v", plan.volumes)
	}
	if !strings.Contains(plan.sambaConfig, "write list = alice") ||
		!strings.Contains(plan.nfsConfig, "anonuid=1000,anongid=1000") ||
		!plan.FreshAgainst(plan.Freshness()) {
		t.Fatalf("plan lost service configuration or freshness contract: %+v", plan)
	}
}

func TestSMBOnlyPlanRequiresGrantedUnixUID(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.NFS.Exports = []nfsconfig.Export{}
	if _, err := Build(config, active, identity, storage); err != nil {
		t.Fatal("valid SMB-only control refused:", err)
	}
	identity.UnixUIDs = []uint32{}
	plan, err := Build(config, active, identity, storage)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("SMB grant accepted without its Unix UID: %v", err)
	}
	samba, nfs := plan.RenderedCandidates()
	if samba != "" || nfs != "" || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("incoherent identity returned a usable partial candidate")
	}
}

func TestSMBOnlyPlanRequiresGrantedUnixPrimaryGID(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.NFS.Exports = []nfsconfig.Export{}
	identity.UnixGIDs = []uint32{identity.Registry.Accounts[0].GID + 1}
	plan, err := Build(config, active, identity, storage)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("SMB grant accepted without its exact Unix primary GID: %v", err)
	}
	samba, nfs := plan.RenderedCandidates()
	if samba != "" || nfs != "" || plan.FreshAgainst(plan.Freshness()) {
		t.Fatal("incoherent primary group returned a usable partial candidate")
	}
}

func TestPlanRendersSambaNSSForExactGrantedPrivateIdentity(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	passwd, group, nss, err := plan.SambaNSSCandidates()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(passwd, "alice:!:1000:1000::/:/sbin/nologin\n") ||
		!strings.Contains(group, "alice:!:1000:\n") || !unixidentity.FilesOnlyNSS([]byte(nss)) {
		t.Fatal("candidate lost locked private identity or files-only NSS")
	}
	observed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal("generated documents failed independent Unix parser:", err)
	}
	status, err := observed.Assess(identity.Registry.Accounts[0])
	if err != nil || status != unixidentity.Observed {
		t.Fatal("generated private group did not resolve to granted native identity")
	}
}

func TestSambaNSSRefusesZeroPlanAndDoesNotAliasInput(t *testing.T) {
	passwd, group, nss, err := (Plan{}).SambaNSSCandidates()
	if !errors.Is(err, ErrNotReady) || passwd != "" || group != "" || nss != "" {
		t.Fatal("zero plan returned usable NSS")
	}
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _, err := plan.SambaNSSCandidates()
	if err != nil {
		t.Fatal(err)
	}
	identity.Registry.Accounts[0].Name = "changed"
	config.Shares.Users[0].Name = "changed"
	after, _, _, err := plan.SambaNSSCandidates()
	if err != nil || after != before {
		t.Fatal("caller mutation changed compiled NSS candidate")
	}
}

func TestSambaNSSOmitsUngrantedAndRetiredAccountsWithoutDiscardingReservations(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	registry, err := identity.Registry.Create(identity.Registry.Revision, "unused", "olduser", serviceaccounts.Reservations{
		UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{serviceaccounts.Disabled, serviceaccounts.Retired} {
		if state == serviceaccounts.Retired {
			registry, err = registry.SetState(registry.Revision, "unused", state)
			if err != nil {
				t.Fatal(err)
			}
		}
		identity.Registry = registry
		plan, err := Build(config, active, identity, storage)
		if err != nil {
			t.Fatal(err)
		}
		passwd, group, _, err := plan.SambaNSSCandidates()
		if err != nil || strings.Contains(passwd, "olduser") || strings.Contains(group, "olduser") {
			t.Fatal("unused/retired identity appeared in granted NSS")
		}
		if len(identity.Registry.Accounts) != 2 || identity.Registry.Accounts[1].UID != 1001 {
			t.Fatal("rendering removed permanent reservation")
		}
	}
}

func TestSambaNSSDoesNotInventCollidingNogroup(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	identity.Registry.Accounts[0].Name = "nogroup"
	identity.Samba[0].Journal.Account.Name = "nogroup"
	identity.Samba[0].Observation.Name = "nogroup"
	config.Shares.Users[0].Name = "nogroup"
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	passwd, group, _, err := plan.SambaNSSCandidates()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal("valid managed nogroup collided with system group:", err)
	}
	if status, err := observed.Assess(identity.Registry.Accounts[0]); err != nil || status != unixidentity.Observed {
		t.Fatal("managed private nogroup identity did not resolve")
	}
}

func TestSambaNSSMaximumGrantedRosterIsBoundedAndOrderIndependent(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	identity.Registry.Accounts = []serviceaccounts.Account{}
	identity.UnixUIDs, identity.UnixGIDs = []uint32{}, []uint32{}
	identity.Samba = []SambaIdentity{}
	config.Shares.Users = []shareconfig.User{}
	config.Shares.Shares[0].Grants = []shareconfig.Grant{}
	for i := 0; i < shareconfig.MaxUsers; i++ {
		account := serviceaccounts.Account{ID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("u%031d", i),
			UID: uint32(1000 + i), GID: uint32(1000 + i), State: serviceaccounts.Enabled}
		identity.Registry.Accounts = append(identity.Registry.Accounts, account)
		identity.UnixUIDs = append(identity.UnixUIDs, account.UID)
		identity.UnixGIDs = append(identity.UnixGIDs, account.GID)
		journalAccount := account
		journalAccount.State = serviceaccounts.Disabled
		sid := fmt.Sprintf("S-1-5-21-1-2-3-%d", 1001+i)
		identity.Samba = append(identity.Samba, SambaIdentity{
			Journal: smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 7,
				NativeRevision: identity.Registry.Revision, Account: journalAccount, SID: sid, Phase: smbprovision.Enabled},
			Observation: smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID, GID: account.GID, SID: sid},
		})
		config.Shares.Users = append(config.Shares.Users, shareconfig.User{ID: account.ID, Name: account.Name})
		config.Shares.Shares[0].Grants = append(config.Shares.Shares[0].Grants, shareconfig.Grant{UserID: account.ID, Access: "rw"})
	}
	first, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal("maximum valid roster refused:", err)
	}
	passwd, group, nss, err := first.SambaNSSCandidates()
	if err != nil || len(passwd)+len(group)+len(nss) > MaxSambaNSSBytes {
		t.Fatal("maximum candidate exceeded combined NSS bound")
	}
	observed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range identity.Registry.Accounts {
		if status, err := observed.Assess(account); err != nil || status != unixidentity.Observed {
			t.Fatal("maximum roster lost private identity")
		}
	}
	slices.Reverse(identity.Registry.Accounts)
	slices.Reverse(identity.Samba)
	slices.Reverse(identity.UnixUIDs)
	slices.Reverse(identity.UnixGIDs)
	slices.Reverse(config.Shares.Users)
	slices.Reverse(config.Shares.Shares[0].Grants)
	second, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	p2, g2, n2, err := second.SambaNSSCandidates()
	if err != nil || passwd != p2 || group != g2 || nss != n2 {
		t.Fatal("NSS rendering depends on input enumeration order")
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
		{"identity fingerprint missing", func(_ *fileservice.Config, _ *uint64, identity *IdentitySnapshot, _ *StorageSnapshot) {
			identity.Fingerprint = [32]byte{}
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
	base := plan.Freshness()
	changed := make(map[string]Freshness)
	value := base
	value.PolicyRevision++
	changed["policy"] = value
	value = base
	value.ActiveRevision++
	changed["active"] = value
	value = base
	value.IdentityGeneration++
	changed["identity generation"] = value
	value = base
	value.IdentityFingerprint = sha256.Sum256([]byte("changed-identity"))
	changed["identity fingerprint"] = value
	value = base
	value.StorageGeneration++
	changed["storage generation"] = value
	value = base
	value.StorageFingerprint[0] ^= 1
	changed["storage fingerprint"] = value
	for name, stale := range changed {
		if plan.FreshAgainst(stale) {
			t.Errorf("stale %s snapshot accepted", name)
		}
	}
	if !plan.FreshAgainst(base) {
		t.Fatal("current exact snapshot rejected")
	}
}

func TestStorageFingerprintBindsMountTupleWhenGenerationIsReused(t *testing.T) {
	config, activeRevision, identity, storage := planInputs(t)
	original, err := Build(config, activeRevision, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	originalFreshness := original.Freshness()

	for name, mutate := range map[string]func(*ObservedVolume){
		"mount ID":     func(volume *ObservedVolume) { volume.MountID++ },
		"device tuple": func(volume *ObservedVolume) { volume.DeviceMinor++ },
	} {
		t.Run(name, func(t *testing.T) {
			changedStorage := storage
			changedStorage.Volumes = append([]ObservedVolume(nil), storage.Volumes...)
			mutate(&changedStorage.Volumes[0])
			changedPlan, err := Build(config, activeRevision, identity, changedStorage)
			if err != nil {
				t.Fatal("changed but valid storage evidence did not compile:", err)
			}
			changedFreshness := changedPlan.Freshness()
			if changedFreshness.StorageGeneration != originalFreshness.StorageGeneration ||
				changedFreshness.StorageFingerprint == originalFreshness.StorageFingerprint ||
				original.FreshAgainst(changedFreshness) {
				t.Fatalf("same generation hid a changed storage tuple: original=%+v changed=%+v", originalFreshness, changedFreshness)
			}
		})
	}
}

func TestStorageFingerprintIsOrderIndependentAndBindsReadOnlyState(t *testing.T) {
	first := StorageSnapshot{Complete: true, Generation: 9, Volumes: []ObservedVolume{
		{VolumeID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", MountPath: "/srv/phantowd/volumes/bulk",
			Compatibility: CompatibilityQualified, MountID: 101, DeviceMajor: 8, DeviceMinor: 1},
		{VolumeID: "archive", FilesystemUUID: "22222222-3333-4444-5555-666666666666", MountPath: "/srv/phantowd/volumes/archive",
			Compatibility: CompatibilityUnqualified, MountID: 102, DeviceMajor: 8, DeviceMinor: 2, ReadOnly: true},
	}}
	second := first
	second.Volumes = []ObservedVolume{first.Volumes[1], first.Volumes[0]}
	if fingerprintStorageSnapshot(first) != fingerprintStorageSnapshot(second) {
		t.Fatal("storage fingerprint depends on volume enumeration order")
	}
	second.Volumes = append([]ObservedVolume(nil), first.Volumes...)
	second.Volumes[1].ReadOnly = false
	if fingerprintStorageSnapshot(first) == fingerprintStorageSnapshot(second) {
		t.Fatal("storage fingerprint ignored read-only state")
	}
	second = first
	first.OwnerFingerprint = sha256.Sum256([]byte("owner-set-a"))
	second.OwnerFingerprint = sha256.Sum256([]byte("owner-set-b"))
	if fingerprintStorageSnapshot(first) == fingerprintStorageSnapshot(second) {
		t.Fatal("storage fingerprint ignored the mounted-owner set evidence")
	}
}

func TestIdentityAndStorageEvidenceCannotBeSerialized(t *testing.T) {
	config, activeRevision, identity, storage := planInputs(t)
	plan, err := Build(config, activeRevision, identity, storage)
	if err != nil {
		t.Fatal("build serialization fixture:", err)
	}
	for name, value := range map[string]any{"identity": identity, "storage": storage, "freshness": plan.Freshness()} {
		if _, err := json.Marshal(value); err == nil {
			t.Errorf("%s evidence was serialized", name)
		}
	}
	var decodedIdentity IdentitySnapshot
	if err := json.Unmarshal([]byte(`{"complete":true}`), &decodedIdentity); err == nil {
		t.Fatal("identity evidence was deserialized")
	}
	var decodedStorage StorageSnapshot
	if err := json.Unmarshal([]byte(`{"complete":true}`), &decodedStorage); err == nil {
		t.Fatal("storage evidence was deserialized")
	}
	var decodedFreshness Freshness
	if err := json.Unmarshal([]byte(`{"storage_generation":1}`), &decodedFreshness); err == nil {
		t.Fatal("freshness evidence was deserialized")
	}
}

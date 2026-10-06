//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func emptyQEMUFileServiceConfig() fileservice.Config {
	shares := shareconfig.Config{
		Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 1,
		Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{},
	}
	nfs := nfsconfig.Policy{
		Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
		Exports: []nfsconfig.Export{},
	}
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: nfs}
}

// This synthetic plan fixture tests only the internal compiler. It constructs
// no mount, reads no disk, and never connects candidate text to a service.
const qemuPlannerVolumeID shareconfig.VolumeID = "qemu-plan"

func syntheticQEMUStorageSnapshot(volumeID shareconfig.VolumeID, generation uint64) fileserviceplan.StorageSnapshot {
	return fileserviceplan.StorageSnapshot{Complete: true, Generation: generation, Volumes: []fileserviceplan.ObservedVolume{{
		VolumeID: volumeID, FilesystemUUID: qemuNFSVolumeUUID,
		MountPath:     shareconfig.VolumeMountRoot + "/" + string(volumeID),
		Compatibility: fileserviceplan.CompatibilityQualified, MountID: 31, DeviceMajor: 8, DeviceMinor: 17,
	}}}
}

func buildQEMUFileServicePlan(volumeID shareconfig.VolumeID, storage fileserviceplan.StorageSnapshot) (fileserviceplan.Plan, error) {
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		return fileserviceplan.Plan{}, errors.New("QEMU plan fixture registry initialization failed")
	}
	registry, err = registry.Create(registry.Revision, "writer", "alice", serviceaccounts.Reservations{
		UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{},
	})
	if err != nil {
		return fileserviceplan.Plan{}, errors.New("QEMU plan fixture account reservation failed")
	}
	registry, err = registry.SetState(registry.Revision, "writer", serviceaccounts.Enabled)
	if err != nil {
		return fileserviceplan.Plan{}, errors.New("QEMU plan fixture account activation failed")
	}
	account := registry.Accounts[0]
	sambaAccount := account
	sambaAccount.State = serviceaccounts.Disabled
	journal := smbprovision.Journal{
		Format: smbprovision.Format, SchemaVersion: 1, Revision: 7,
		NativeRevision: registry.Revision, Account: sambaAccount,
		SID: "S-1-5-21-1-2-3-1001", Phase: smbprovision.Enabled,
	}
	identity := fileserviceplan.IdentitySnapshot{
		Complete: true, Generation: 9, Fingerprint: sha256.Sum256([]byte("phantowd-qemu-synthetic-identity-v1")), Registry: registry,
		UnixUIDs: []uint32{account.UID}, UnixGIDs: []uint32{account.GID},
		Samba: []fileserviceplan.SambaIdentity{{Journal: journal, Observation: smbprovision.Observation{
			Present: true, Name: account.Name, UID: account.UID, GID: account.GID,
			SID: journal.SID,
		}}},
	}
	shares := shareconfig.Config{
		Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 4,
		Volumes: []shareconfig.Volume{{ID: volumeID, FilesystemUUID: qemuNFSVolumeUUID}},
		Users:   []shareconfig.User{{ID: account.ID, Name: account.Name}},
		Shares: []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: volumeID, RelativePath: "books",
			Grants: []shareconfig.Grant{{UserID: account.ID, Access: "rw"}}}},
	}
	nfs := nfsconfig.Policy{
		Format: nfsconfig.Format, SchemaVersion: 1, Revision: 4, VolumeRevision: 4,
		Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: volumeID, RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all",
				AnonymousUID: account.UID, AnonymousGID: account.GID, Security: "sys"}}}},
	}
	config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 4, Shares: shares, NFS: nfs}
	plan, err := fileserviceplan.Build(config, 2, identity, storage)
	if err != nil {
		return fileserviceplan.Plan{}, errors.New("QEMU file-service candidate-plan compilation failed")
	}
	return plan, nil
}

func identityFingerprintForQEMUPlan() [32]byte {
	return sha256.Sum256([]byte("phantowd-qemu-synthetic-identity-v1"))
}

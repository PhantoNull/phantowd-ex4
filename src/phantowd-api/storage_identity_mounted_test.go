// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"testing"
)

func TestCorrelateMountedStorageIdentityResolvesMountedMDFilesystem(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}

	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{{
			anchor: "/srv/media", filesystemUUID: filesystemUUID,
			mountID: 70001, deviceMajor: 9, deviceMinor: 0,
		}},
		conflictingUUIDs: []string{},
	}

	identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
	if err != nil || len(identities) != 1 {
		t.Fatalf("mounted filesystem identity was not correlated: %+v, %v", identities, err)
	}
	identity := identities[0]
	if identity.anchor != "/srv/media" || identity.filesystemUUID != filesystemUUID || identity.mountID != 70001 ||
		identity.sourceName != "md0" || identity.filesystemUUIDConflict || len(identity.arrays) != 1 ||
		identity.arrays[0].arrayName != "md0" || len(identity.physicalDisks) != 2 ||
		identity.physicalDisks[0].diskName != "sda" || identity.physicalDisks[1].diskName != "sdb" {
		t.Fatalf("mounted filesystem was not linked to its transient MD and disk observations: %+v", identity)
	}
}

func TestCorrelateMountedStorageIdentityTreatsSameDeviceUUIDMountsAsAliases(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}

	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{
			{anchor: "/srv/media", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9, deviceMinor: 0},
			{anchor: "/srv/media-alias", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9, deviceMinor: 0},
		},
		conflictingUUIDs: []string{},
	}

	identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
	if err != nil || len(identities) != 2 {
		t.Fatalf("aliases of one mounted device were not correlated: %+v, %v", identities, err)
	}
	for _, identity := range identities {
		if identity.filesystemUUIDConflict || identity.sourceName != "md0" {
			t.Fatalf("aliases were misclassified as cloned filesystem identity: %+v", identity)
		}
	}
}

func TestCorrelateMountedStorageIdentityMarksFilesystemUUIDClonesAcrossDevices(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}

	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{
			{anchor: "/srv/media", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9, deviceMinor: 0},
			{anchor: "/srv/clone", filesystemUUID: filesystemUUID, mountID: 70002, deviceMajor: 8, deviceMinor: 1},
		},
		conflictingUUIDs: []string{filesystemUUID},
	}

	identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
	if err != nil || len(identities) != 2 {
		t.Fatalf("distinct devices with a cloned filesystem UUID were not correlated: %+v, %v", identities, err)
	}
	for _, identity := range identities {
		if !identity.filesystemUUIDConflict {
			t.Fatalf("filesystem UUID clone was not marked ambiguous: %+v", identity)
		}
	}
}

func TestCorrelateMountedStorageIdentityRejectsPartialDeviceResolution(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}

	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{
			{anchor: "/srv/media", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9, deviceMinor: 0},
			{anchor: "/srv/missing", filesystemUUID: "77777777-8888-9999-aaaa-bbbbbbbbbbbb", mountID: 70002, deviceMajor: 99, deviceMinor: 99},
		},
		conflictingUUIDs: []string{},
	}

	identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
	if err == nil || identities != nil {
		t.Fatalf("partial mounted identity result escaped an unresolved source: %+v, %v", identities, err)
	}
}

func TestCorrelateMountedStorageIdentityRejectsStaleMDGenerationBinding(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}
	staleBindings := []mdArrayStorageIdentity{cloneMDArrayStorageIdentity(arrayBindings[0])}
	staleBindings[0].arrayDiskSeq++

	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{{
			anchor: "/srv/media", filesystemUUID: "66666666-7777-8888-9999-aaaaaaaaaaaa",
			mountID: 70001, deviceMajor: 9, deviceMinor: 0,
		}},
		conflictingUUIDs: []string{},
	}
	identities, err := correlateMountedStorageIdentity(storage, staleBindings, mounted)
	if err == nil || identities != nil {
		t.Fatalf("stale MD generation binding was accepted: %+v, %v", identities, err)
	}
}

func TestCorrelateMountedStorageIdentityRejectsMissingCloneConflict(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}
	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{
			{anchor: "/srv/media", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9, deviceMinor: 0},
			{anchor: "/srv/clone", filesystemUUID: filesystemUUID, mountID: 70002, deviceMajor: 8, deviceMinor: 1},
		},
		conflictingUUIDs: []string{},
	}

	identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
	if err == nil || identities != nil {
		t.Fatalf("inconsistent clone summary was accepted as non-conflicting: %+v, %v", identities, err)
	}
}

func TestCorrelateMountedStorageIdentityRejectsInvalidAnchorAndUUID(t *testing.T) {
	storage, arrays := fixtureMDStorageIdentity()
	arrayBindings, err := correlateMDStorageIdentity(storage, arrays)
	if err != nil {
		t.Fatalf("MD identity fixture was not valid: %v", err)
	}
	const filesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	cases := []struct {
		name  string
		mount mountedFilesystemObservation
	}{
		{
			name:  "root anchor",
			mount: mountedFilesystemObservation{anchor: "/", filesystemUUID: filesystemUUID, mountID: 70001, deviceMajor: 9},
		},
		{
			name:  "noncanonical UUID",
			mount: mountedFilesystemObservation{anchor: "/srv/media", filesystemUUID: "66666666-7777-8888-9999-AAAAAAAAAAAA", mountID: 70001, deviceMajor: 9},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mounted := mountedFilesystemInventory{mounts: []mountedFilesystemObservation{test.mount}, conflictingUUIDs: []string{}}
			identities, err := correlateMountedStorageIdentity(storage, arrayBindings, mounted)
			if err == nil || identities != nil {
				t.Fatalf("malformed mounted identity was accepted: %+v, %v", identities, err)
			}
		})
	}
}

func TestCorrelateMountedStorageIdentityKeepsDirectDiskEvidenceQualityExplicit(t *testing.T) {
	storage, _ := fixtureMDStorageIdentity()
	storage.Observations = append([]blockObservation{}, storage.Observations[1:]...)
	storage.DeviceCount = len(storage.Observations)
	storage.Observations[0].SerialStatus = identityUnavailable
	storage.Observations[0].WWNStatus = identityUnavailable
	storage.Observations[0].serialEvidence = [32]byte{}
	storage.Observations[0].wwnEvidence = [32]byte{}

	mounted := mountedFilesystemInventory{
		mounts: []mountedFilesystemObservation{{
			anchor: "/srv/direct", filesystemUUID: "66666666-7777-8888-9999-aaaaaaaaaaaa",
			mountID: 70001, deviceMajor: 8, deviceMinor: 1,
		}},
		conflictingUUIDs: []string{},
	}
	identities, err := correlateMountedStorageIdentity(storage, []mdArrayStorageIdentity{}, mounted)
	if err != nil || len(identities) != 1 {
		t.Fatalf("direct mounted filesystem could not be correlated as a transient observation: %+v, %v", identities, err)
	}
	identity := identities[0]
	if len(identity.arrays) != 0 || len(identity.physicalDisks) != 1 || identity.physicalDisks[0].diskName != "sda" ||
		identity.physicalDisks[0].serialStatus != identityUnavailable || identity.physicalDisks[0].wwnStatus != identityUnavailable ||
		identity.physicalDisks[0].serialEvidence != ([32]byte{}) || identity.physicalDisks[0].wwnEvidence != ([32]byte{}) {
		t.Fatalf("missing stable identifiers were hidden or promoted: %+v", identity)
	}
}

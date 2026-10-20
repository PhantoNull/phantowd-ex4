//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func nfsInputsCandidate(t *testing.T, enabled bool, network string) fileserviceplan.NFSv3Candidate {
	t.Helper()
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	nfs := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}
	if enabled {
		nfs.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: network, Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	}
	plan, err := fileserviceplan.Build(fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: nfs}, 0,
		fileserviceplan.IdentitySnapshot{Complete: true, Generation: 1, Fingerprint: sha256.Sum256([]byte("nfs-inputs-test")), Registry: registry,
			UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}},
		fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid,
			MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestNFSConfigurationUsesSameCandidateAndExplicitState(t *testing.T) {
	candidate := nfsInputsCandidate(t, true, "127.0.0.1/32")
	documents, err := runtimebundle.NFSFixtureConfigurationQEMU(candidate)
	_, table, _, _ := candidate.Documents()
	if err != nil || len(documents) != 9 || documents["exports"] != table {
		t.Fatal("configuration lost the same candidate", err)
	}
	const expected = "[mountd]\nstate-directory-path=/run/nfs\nreverse-lookup=n\nmanage-gids=n\n[nfsd]\nvers2=n\nvers3=y\nvers4=n\ntcp=y\nudp=n\n"
	if documents["nfs.conf"] != expected {
		t.Fatal("implicit state or widened protocol profile")
	}
}

func TestNFSConfigurationRefusesUnsupportedFamilyAndDisabled(t *testing.T) {
	if documents, err := runtimebundle.NFSFixtureConfigurationQEMU(nfsInputsCandidate(t, true, "::1/128")); documents != nil || !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("IPv4-only fixture accepted IPv6 exports", err)
	}
	if documents, err := runtimebundle.NFSFixtureConfigurationQEMU(nfsInputsCandidate(t, false, "")); documents != nil || !errors.Is(err, runtimebundle.ErrUnavailable) {
		t.Fatal("disabled policy gained runtime documents", err)
	}
	if documents, err := runtimebundle.NFSFixtureConfigurationQEMU(fileserviceplan.NFSv3Candidate{}); documents != nil || !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("invalid candidate gained runtime documents", err)
	}
}

func TestNFSConfigurationReturnsIndependentFilesOnlyDocuments(t *testing.T) {
	candidate := nfsInputsCandidate(t, true, "127.0.0.1/32")
	first, err := runtimebundle.NFSFixtureConfigurationQEMU(candidate)
	if err != nil {
		t.Fatal(err)
	}
	first["exports"] = "untrusted replacement"
	delete(first, "nfs.conf")
	second, err := runtimebundle.NFSFixtureConfigurationQEMU(candidate)
	_, table, _, _ := candidate.Documents()
	if err != nil || len(second) != 9 || second["exports"] != table || second["nfs.conf"] == "" ||
		second["netconfig"] != "local tpi_cots_ord - loopback - - -\ntcp tpi_cots_ord v inet tcp - -\n" ||
		second["hosts"] != "127.0.0.1 localhost\n" || second["services"] != "sunrpc 111/tcp rpcbind portmapper\nnfs 2049/tcp\nmountd 20048/tcp\n" {
		t.Fatal("caller mutation, DNS, or unsupported transport changed profile", err)
	}
}

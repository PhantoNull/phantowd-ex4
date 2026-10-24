// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Synthetic observations qualify data projection only, never a storage lease.
func nfsDocumentCandidate(t testing.TB, exports []nfsconfig.Export) fileserviceplan.NFSv3Candidate {
	t.Helper()
	registry, err := serviceaccounts.New(2000, 3000)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 7,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
			Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 7, VolumeRevision: 7, Exports: exports}}
	identity := fileserviceplan.IdentitySnapshot{Complete: true, Generation: 19,
		Fingerprint: sha256.Sum256([]byte("synthetic-nfs-documents")), Registry: registry,
		UnixUIDs: []uint32{65534}, UnixGIDs: []uint32{65534}, Samba: []fileserviceplan.SambaIdentity{}}
	storage := fileserviceplan.StorageSnapshot{Complete: true, Generation: 23, Volumes: []fileserviceplan.ObservedVolume{{
		VolumeID: "bulk", FilesystemUUID: uuid, MountPath: shareconfig.VolumeMountRoot + "/bulk",
		Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}}
	plan, err := fileserviceplan.Build(config, 0, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func nfsDocumentExport() nfsconfig.Export {
	return nfsconfig.Export{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "Books & Comics",
		Clients: []nfsconfig.Client{{Network: "192.0.2.1/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}
}

func TestNFSDocumentsPreserveCompleteSamePlanTable(t *testing.T) {
	candidate := nfsDocumentCandidate(t, []nfsconfig.Export{nfsDocumentExport()})
	_, table, _, _ := candidate.Documents()
	enabled, documents, err := NFSv3Documents(candidate)
	if err != nil || !enabled || len(documents) != 3 || documents["etc/exports"] != table {
		t.Fatal("projection lost the complete candidate", err)
	}
	for _, setting := range []string{"vers2=no", "vers3=yes", "vers4=no", "tcp=yes", "udp=no"} {
		if !strings.Contains(documents["etc/nfs.conf"], setting+"\n") {
			t.Fatal("missing declared protocol setting", setting)
		}
	}
	if !strings.Contains(documents["etc/netconfig"], "local ") || !strings.Contains(documents["etc/netconfig"], "tcp ") {
		t.Fatal("missing RPC transport data")
	}
	documents["etc/exports"] = "caller replacement"
	_, again, err := NFSv3Documents(candidate)
	if err != nil || again["etc/exports"] != table {
		t.Fatal("caller changed later projection", err)
	}
}

func TestNFSDocumentsBoundCompleteSetBeforeReturningAnyOutput(t *testing.T) {
	_, baseline, err := NFSv3Documents(nfsDocumentCandidate(t, []nfsconfig.Export{nfsDocumentExport()}))
	if err != nil {
		t.Fatal(err)
	}
	fixed := len(baseline["etc/netconfig"]) + len(baseline["etc/nfs.conf"])
	pathFor := func(prefix string, size int) string {
		tail := []byte(strings.Repeat("x", size-len(prefix)))
		for i := 99; i < len(tail)-1; i += 100 {
			tail[i] = '/'
		}
		return prefix + string(tail)
	}
	exports := make([]nfsconfig.Export, 58)
	for i := range exports {
		exports[i] = nfsDocumentExport()
		exports[i].ID = fmt.Sprintf("aaaaaaaa-bbbb-cccc-dddd-%012x", i+1)
		exports[i].RelativePath = pathFor(fmt.Sprintf("e%03d/", i), 904)
	}
	large := nfsDocumentCandidate(t, exports)
	_, table, _, _ := large.Documents()
	overflow := len(table) + fixed - (64 << 10)
	if overflow <= 0 || overflow >= 899 {
		t.Fatal("synthetic policy no longer spans the exact configuration boundary", overflow)
	}
	exports[57].RelativePath = pathFor("e057/", 904-overflow)
	exact := nfsDocumentCandidate(t, exports)
	enabled, documents, err := NFSv3Documents(exact)
	if err != nil || !enabled || len(documents["etc/exports"])+fixed != 64<<10 {
		t.Fatal("aggregate exact-fit configuration was refused", err)
	}
	exports[57].RelativePath += "x"
	enabled, documents, err = NFSv3Documents(nfsDocumentCandidate(t, exports))
	if enabled || documents != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("one-byte aggregate overflow returned partial configuration", err)
	}
}

func TestNFSDocumentsDistinguishInvalidFromDisabledWithoutOutput(t *testing.T) {
	if enabled, documents, err := NFSv3Documents(fileserviceplan.NFSv3Candidate{}); enabled || documents != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid candidate produced configuration", err)
	}
	disabled := nfsDocumentCandidate(t, []nfsconfig.Export{})
	if enabled, documents, err := NFSv3Documents(disabled); enabled || documents != nil || err != nil {
		t.Fatal("valid disabled policy became a missing-evidence failure or produced configuration", err)
	}
}

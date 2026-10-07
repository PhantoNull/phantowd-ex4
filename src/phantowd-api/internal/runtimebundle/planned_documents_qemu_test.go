//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Synthetic snapshots test pure rendering, not actual Owner/mount authority.
func plannedDocumentCandidate(t *testing.T) fileserviceplan.SambaIsolatedCandidate {
	t.Helper()
	registry, err := serviceaccounts.New(2000, 3000)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"qpmanaged", "qpsecond"} {
		registry, err = registry.Create(registry.Revision, name, name, serviceaccounts.Reservations{
			UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		registry, err = registry.SetState(registry.Revision, name, serviceaccounts.Enabled)
		if err != nil {
			t.Fatal(err)
		}
	}
	identity := fileserviceplan.IdentitySnapshot{Complete: true, Generation: 19,
		Fingerprint: sha256.Sum256([]byte("synthetic-planned-documents-only")), Registry: registry}
	for index, account := range registry.Accounts {
		view := account
		view.State = serviceaccounts.Disabled
		sid := []string{"S-1-5-21-1-2-3-2000", "S-1-5-21-1-2-3-2001"}[index]
		identity.UnixUIDs = append(identity.UnixUIDs, account.UID)
		identity.UnixGIDs = append(identity.UnixGIDs, account.GID)
		identity.Samba = append(identity.Samba, fileserviceplan.SambaIdentity{
			Journal: smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 7,
				NativeRevision: registry.Revision, Account: view, SID: sid, Phase: smbprovision.Enabled},
			Observation: smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID, GID: account.GID, SID: sid},
		})
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 7,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
			Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}},
			Users:   []shareconfig.User{{ID: "qpmanaged", Name: "qpmanaged"}, {ID: "qpsecond", Name: "qpsecond"}},
			Shares: []shareconfig.Share{
				{ID: "readonly", Name: "ReadOnly", VolumeID: "bulk", RelativePath: "books/ro",
					Grants: []shareconfig.Grant{{UserID: "qpsecond", Access: "ro"}}},
				{ID: "writable", Name: "Writable", VolumeID: "bulk", RelativePath: "books/rw",
					Grants: []shareconfig.Grant{{UserID: "qpsecond", Access: "rw"}}},
			}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 7, VolumeRevision: 7, Exports: []nfsconfig.Export{}},
	}
	storage := fileserviceplan.StorageSnapshot{Complete: true, Generation: 23,
		Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid,
			MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified,
			MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}}
	plan, err := fileserviceplan.Build(config, 0, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.SambaIsolatedCandidate()
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestPlannedDocumentsPreserveCompleteCandidateAndOmitUngranted(t *testing.T) {
	candidate := plannedDocumentCandidate(t)
	docs, err := SambaPlannedDataDocumentsQEMU(candidate)
	if err != nil || len(docs) != 7 {
		t.Fatal("candidate refused", err)
	}
	passwd, group, nss, sections, _, err := candidate.Documents()
	if err != nil || docs["passwd"] != passwd || docs["group"] != group || docs["nsswitch.conf"] != nss ||
		docs["samba/smb.conf"] != nativeSambaGlobalsQEMU+sections {
		t.Fatal("rendered configuration lost the exact immutable Plan documents")
	}
	if !strings.Contains(passwd, "qpsecond:!:2001:2001:") || strings.Contains(passwd, "qpmanaged:") ||
		strings.Contains(group, "qpmanaged:") || strings.Contains(docs["samba/smb.conf"], "/srv/phantowd/volumes/") {
		t.Fatal("rendering broadened identity or source-path exposure")
	}
	for _, rule := range []string{"path = /shares/readonly", "path = /shares/writable",
		"read list = qpsecond", "write list = qpsecond", "guest ok = no", "wide links = no", "follow symlinks = no"} {
		if !strings.Contains(docs["samba/smb.conf"], rule) {
			t.Fatal("missing Plan rule", rule)
		}
	}
	docs["passwd"], docs["samba/smb.conf"] = "replacement", "replacement"
	delete(docs, "group")
	fresh, err := SambaPlannedDataDocumentsQEMU(candidate)
	if err != nil || fresh["passwd"] != passwd || fresh["group"] != group || fresh["samba/smb.conf"] != nativeSambaGlobalsQEMU+sections {
		t.Fatal("caller map mutation changed candidate or later output")
	}
}

func TestPlannedDocumentsRefuseZeroCandidateWithoutPartialOutput(t *testing.T) {
	if docs, err := SambaPlannedDataDocumentsQEMU(fileserviceplan.SambaIsolatedCandidate{}); docs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("absent Plan supplied configuration", err)
	}
}

func TestPlannedDocumentsAggregateBudgetIsExactAndAtomic(t *testing.T) {
	fixed := int64(len(nativeSambaGlobalsQEMU) + len("127.0.0.1 localhost\n") +
		len("tcp 6 TCP\nudp 17 UDP\n") + len("microsoft-ds 445/tcp\n") + 3)
	exact := strings.Repeat("x", int(maxConfigurationBytes-fixed))
	docs, err := boundedPlannedDocumentsQEMU("p", "g", "n", exact)
	if err != nil || len(docs) != 7 {
		t.Fatal("exact aggregate bound refused", err)
	}
	var bytes int64
	for _, contents := range docs {
		bytes += int64(len(contents))
	}
	if bytes != maxConfigurationBytes {
		t.Fatal("budget was not aggregate", bytes)
	}
	if docs, err := boundedPlannedDocumentsQEMU("p", "g", "n", exact+"x"); docs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("overflow supplied partial output", err)
	}
	for index := range 4 {
		values := []string{"p", "g", "n", "s"}
		values[index] = ""
		if docs, err := boundedPlannedDocumentsQEMU(values[0], values[1], values[2], values[3]); docs != nil || err == nil {
			t.Fatal("empty candidate part supplied partial output")
		}
	}
}

func TestNativeGlobalsRemainExactAndSharedStateOnly(t *testing.T) {
	// Independent pre-refactor expectation; not constructed from the new constant.
	want := strings.Join([]string{
		"[global]", "server role = standalone server", "security = user", "map to guest = Never",
		"interfaces = 127.0.0.1", "bind interfaces only = yes", "smb ports = 1445",
		"server min protocol = SMB3_00", "server max protocol = SMB3_11", "server signing = mandatory",
		"load printers = no", "printing = bsd", "printcap name = /dev/null", "disable spoolss = yes",
		"dns proxy = no", "name resolve order = host", "dos charset = CP850", "unix charset = UTF-8",
		"private dir = /state/private", "lock directory = /state/lock", "state directory = /state/state",
		"cache directory = /state/cache", "pid directory = /state/pid", "ncalrpc dir = /state/rpc",
		"passdb backend = tdbsam:/state/private/passdb.tdb", "log file = /state/log.smbd", "",
	}, "\n")
	if nativeSambaGlobalsQEMU != want {
		t.Fatal("existing management globals changed")
	}
}

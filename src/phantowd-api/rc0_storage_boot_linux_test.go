// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestRC0StorageApprovalRequiresExactMountAndBacking(t *testing.T) {
	proof := `{"format":"phantowd-rc0-storage-v1","registry_revision":3,"volumes":[{"id":"boot-data","filesystem_uuid":"11111111-2222-3333-4444-555555555555","mount_id":123,"root_inode":2,"device_major":8,"device_minor":0,"read_only":false,"disks":[{"wwn_sha256":"` +
		strings.Repeat("a", 64) + `"}],"arrays":[]}]}`
	digest := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
	approval, err := decodeRC0StorageApproval([]byte(proof), digest(proof))
	if err != nil || approval.RegistryRevision != 3 || len(approval.Volumes) != 1 {
		t.Fatalf("valid backing rejected: %v", err)
	}
	grant, err := approval.Volumes[0].grant()
	if err != nil || grant.mount.SourcePath != "/run/phantowd-data-sources/boot-data" ||
		grant.mount.Expected.MountID != 123 || !grant.mount.Expected.RequireWritable {
		t.Fatalf("approval did not produce the fixed mount grant: %v", err)
	}
	if _, err := decodeRC0StorageApproval([]byte(proof), digest(proof+" ")); err == nil {
		t.Fatal("altered boot approval hash was accepted")
	}
	withNFS := strings.TrimSuffix(proof, "}") + `,"nfs":{"address":"192.0.2.2","ingress_index":4}}`
	approval, err = decodeRC0StorageApproval([]byte(withNFS), digest(withNFS))
	if err != nil || approval.NFS == nil || approval.NFS.Address.String() != "192.0.2.2" || approval.NFS.IngressIndex != 4 {
		t.Fatalf("valid NFS endpoint rejected: %v", err)
	}
	withSMB := strings.TrimSuffix(withNFS, "}") + `,"smb":{"address":"192.0.2.3","ingress_index":5}}`
	approval, err = decodeRC0StorageApproval([]byte(withSMB), digest(withSMB))
	if err != nil || approval.NFS == nil || approval.SMB == nil ||
		approval.SMB.Address.String() != "192.0.2.3" || approval.SMB.IngressIndex != 5 {
		t.Fatalf("valid SMB endpoint rejected: %v", err)
	}
	for _, changed := range []string{
		strings.Replace(proof, `"id":"boot-data"`, `"id":"../other"`, 1),
		strings.Replace(proof, `"id":"boot-data"`, `"id":"boot-data","source":"/elsewhere"`, 1),
		strings.Replace(proof, `"registry_revision":3`, `"registry_revision":0`, 1),
		strings.Replace(proof, `"read_only":false,`, "", 1),
		strings.Replace(proof, `"device_minor":0,`, "", 1),
		strings.Replace(proof, strings.Repeat("a", 64), strings.Repeat("0", 64), 1),
		strings.Replace(proof, `"arrays":[]`, `"arrays":null`, 1),
		strings.Replace(withNFS, "192.0.2.2", "127.0.0.1", 1),
		strings.Replace(withNFS, "192.0.2.2", "::ffff:192.0.2.2", 1),
		strings.Replace(withNFS, `"ingress_index":4`, `"ingress_index":0`, 1),
		strings.Replace(withNFS, `"ingress_index":4`, `"ingress_index":4,"nfsd":"/tmp/nfsd"`, 1),
		strings.Replace(withSMB, "192.0.2.3", "224.0.0.1", 1),
		strings.Replace(withSMB, `"ingress_index":5`, `"ingress_index":-1`, 1),
		`{"format":"phantowd-rc0-storage-v1","registry_revision":3,"volumes":[],"smb":{"address":"192.0.2.3","ingress_index":5}}`,
	} {
		if _, err := decodeRC0StorageApproval([]byte(changed), digest(changed)); err == nil {
			t.Fatalf("accepted invalid approval: %s", changed)
		}
	}
}

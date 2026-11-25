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
	for _, changed := range []string{
		strings.Replace(proof, `"id":"boot-data"`, `"id":"../other"`, 1),
		strings.Replace(proof, `"id":"boot-data"`, `"id":"boot-data","source":"/elsewhere"`, 1),
		strings.Replace(proof, `"registry_revision":3`, `"registry_revision":0`, 1),
		strings.Replace(proof, `"read_only":false,`, "", 1),
		strings.Replace(proof, `"device_minor":0,`, "", 1),
		strings.Replace(proof, strings.Repeat("a", 64), strings.Repeat("0", 64), 1),
		strings.Replace(proof, `"arrays":[]`, `"arrays":null`, 1),
	} {
		if _, err := decodeRC0StorageApproval([]byte(changed), digest(changed)); err == nil {
			t.Fatalf("accepted invalid approval: %s", changed)
		}
	}
}

//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func exerciseQEMUNFSPolicy() error {
	volumes := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "test-volume", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	const fixture = `{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,
"exports":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","volume_id":"test-volume","relative_path":"books",
"clients":[{"network":"127.0.0.1/32","access":"rw","squash":"all","anonymous_uid":101000,"anonymous_gid":101000,"security":"sys"}]}]}`
	policy, err := nfsconfig.Decode(strings.NewReader(fixture), volumes)
	if err != nil {
		return err
	}
	preview, err := nfsconfig.Build(policy, volumes)
	if err != nil || !strings.Contains(preview.Table, "127.0.0.1/32(rw,sync,secure,root_squash,all_squash,subtree_check,nocrossmnt,sec=sys,anonuid=101000,anongid=101000") ||
		!strings.Contains(preview.Table, "mountpoint=/srv/phantowd/volumes/11111111-2222-3333-4444-555555555555") || !preview.UsesAUTH_SYS {
		return errors.New("NFS preview lost client/mapping/mount constraints")
	}
	for _, invalid := range []string{
		strings.Replace(fixture, `"network":"127.0.0.1/32"`, `"network":"*"`, 1),
		strings.Replace(fixture, `"anonymous_uid":101000`, `"anonymous_uid":0`, 1),
		strings.Replace(fixture, `"squash":"all"`, `"squash":"none"`, 1),
		strings.Replace(fixture, `"volume_revision":1`, `"volume_revision":2`, 1),
	} {
		if _, err := nfsconfig.Decode(strings.NewReader(invalid), volumes); err == nil {
			return errors.New("NFS policy accepted unsafe fixture")
		}
	}
	return nil
}

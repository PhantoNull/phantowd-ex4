// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsipreview

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestConfiguredBackingExposureIsOnlySameVolumePathAdvisory(t *testing.T) {
	for _, tc := range []struct {
		name, path, volume string
		want               int
	}{
		{"root", ".", "bulk", 1},
		{"equal", "luns/not-opened.img", "bulk", 1},
		{"ancestor", "luns", "bulk", 1},
		{"descendant", "luns/not-opened.img/child", "bulk", 1},
		{"component-not-prefix", "luns/not-opened.img-other", "bulk", 0},
		{"sibling", "luns/other.img", "bulk", 0},
		{"case-sensitive", "Luns", "bulk", 0},
		{"different-volume", ".", "other", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture()
			c.FileServices.Shares.Volumes = append(c.FileServices.Shares.Volumes, shareconfig.Volume{ID: "other", FilesystemUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
			c.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
			c.FileServices.Shares.Shares = []shareconfig.Share{{ID: "share", Name: "Private share", VolumeID: shareconfig.VolumeID(tc.volume), RelativePath: tc.path, Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
			c.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-1111-2222-3333-444444444444", VolumeID: shareconfig.VolumeID(tc.volume), RelativePath: tc.path,
				Clients: []nfsconfig.Client{{Network: "198.51.100.1/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
			// Disabled targets and read-only shares still deserve the advisory:
			// neither is proof of runtime isolation or safe file sharing.
			c.ISCSI.Targets[0].State = "disabled"
			before, _ := json.Marshal(c)
			p, err := Build(c)
			if err != nil {
				t.Fatal("valid policy was blocked by advisory", err)
			}
			data, _ := json.Marshal(p)
			var wire struct {
				SchemaVersion int `json:"schema_version"`
				Backings      []struct {
					SMB *int `json:"smb_path_overlap_count"`
					NFS *int `json:"nfs_path_overlap_count"`
				} `json:"backings"`
			}
			if json.Unmarshal(data, &wire) != nil || wire.SchemaVersion != 2 || len(wire.Backings) != 1 || wire.Backings[0].SMB == nil || wire.Backings[0].NFS == nil ||
				*wire.Backings[0].SMB != tc.want || *wire.Backings[0].NFS != tc.want || p.StorageValidated || p.ActivationAvailable {
				t.Fatal("missing or incorrect bounded advisory, or authority granted")
			}
			after, _ := json.Marshal(c)
			if string(before) != string(after) {
				t.Fatal("advisory mutated input")
			}
		})
	}
}

func TestConfiguredBackingExposureCountsEntireRoster(t *testing.T) {
	c := fixture()
	c.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	for i := 0; i < 128; i++ {
		c.FileServices.Shares.Shares = append(c.FileServices.Shares.Shares, shareconfig.Share{ID: fmt.Sprintf("s-%d", i), Name: fmt.Sprintf("Private share %d", i), VolumeID: "bulk", RelativePath: fmt.Sprintf("luns/not-opened.img/child%d", i), Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}})
		c.FileServices.NFS.Exports = append(c.FileServices.NFS.Exports, nfsconfig.Export{ID: fmt.Sprintf("aaaaaaaa-1111-2222-3333-%012x", i+1), VolumeID: "bulk", RelativePath: fmt.Sprintf("luns/not-opened.img/child%d", i),
			Clients: []nfsconfig.Client{{Network: "198.51.100.1/32", Access: "rw", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}})
	}
	p, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(p)
	var wire struct {
		Backings []struct {
			SMB int `json:"smb_path_overlap_count"`
			NFS int `json:"nfs_path_overlap_count"`
		} `json:"backings"`
	}
	if json.Unmarshal(data, &wire) != nil || len(wire.Backings) != 1 || wire.Backings[0].SMB != 128 || wire.Backings[0].NFS != 128 {
		t.Fatal("advisory silently truncated configured definitions")
	}
}

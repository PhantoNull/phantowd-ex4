// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func denseEditConfig(revision uint64) Config {
	c := editConfig(revision)
	c.FileServices.Shares.Users = []shareconfig.User{}
	grants := make([]shareconfig.Grant, 128)
	for i := range grants {
		id := fmt.Sprintf("reader-%d", i)
		c.FileServices.Shares.Users = append(c.FileServices.Shares.Users, shareconfig.User{ID: id, Name: fmt.Sprintf("reader%d", i)})
		grants[i] = shareconfig.Grant{UserID: id, Access: "ro"}
	}
	c.FileServices.Shares.Shares = []shareconfig.Share{}
	for i := 0; i < 32; i++ {
		c.FileServices.Shares.Shares = append(c.FileServices.Shares.Shares, shareconfig.Share{ID: fmt.Sprintf("share-%d", i), Name: fmt.Sprintf("Share %d", i), VolumeID: "bulk", RelativePath: fmt.Sprintf("books/%d", i), Grants: grants})
	}
	clients := make([]nfsconfig.Client, 64)
	for i := range clients {
		clients[i] = nfsconfig.Client{Network: fmt.Sprintf("192.0.2.%d/32", i+1), Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}
	}
	c.FileServices.NFS.Exports = []nfsconfig.Export{}
	for i := 0; i < 16; i++ {
		c.FileServices.NFS.Exports = append(c.FileServices.NFS.Exports, nfsconfig.Export{ID: fmt.Sprintf("66666666-7777-4888-8999-%012x", i+1), VolumeID: "bulk", RelativePath: fmt.Sprintf("exports/%d", i), Clients: clients})
	}
	return c
}

// Dense is a bounded sample, not every maximum or an ARM timing guarantee.
func BenchmarkReplaceViews(b *testing.B) {
	for _, dense := range []bool{false, true} {
		base, next := editConfig(1), editConfig(2)
		name := "small"
		if dense {
			base, next, name = denseEditConfig(1), denseEditConfig(2), "dense"
		}
		if base.Validate() != nil || next.Validate() != nil {
			b.Fatal("invalid benchmark fixture")
		}
		data, err := json.Marshal(base)
		if err != nil {
			b.Fatal("benchmark serialization failed")
		}
		for _, files := range []bool{false, true} {
			direction := "iscsi"
			if files {
				direction = "files"
			}
			b.Run(name+"/"+direction, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				for i := 0; i < b.N; i++ {
					var got Config
					var err error
					if files {
						got, err = ReplaceFileServices(base, next.FileServices)
					} else {
						got, err = ReplaceISCSI(base, next.ISCSI)
					}
					if err != nil || got.Revision != 2 {
						b.Fatal("benchmark edit failed")
					}
				}
			})
		}
	}
}

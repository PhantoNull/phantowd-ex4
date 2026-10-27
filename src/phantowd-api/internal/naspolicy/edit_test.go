// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func editConfig(revision uint64) Config {
	c := testConfig()
	c.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	c.FileServices.Shares.Shares = []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	c.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "66666666-7777-4888-8999-aaaaaaaaaaaa", VolumeID: "bulk", RelativePath: "books",
		Clients: []nfsconfig.Client{{Network: "198.51.100.7/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
	c.Revision = revision
	c.FileServices.Revision = revision
	c.FileServices.Shares.Revision = revision
	c.FileServices.NFS.Revision = revision
	c.FileServices.NFS.VolumeRevision = revision
	c.ISCSI.Revision = revision
	c.ISCSI.VolumeRevision = revision
	return c
}

func policyBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture serialization failed")
	}
	return data
}

func TestReplaceFileServicesRetainsISCSIAndIndependentValues(t *testing.T) {
	base := editConfig(1)
	next := editConfig(2).FileServices
	next.Shares.Shares[0].Grants[0].Access = "rw"
	next.NFS.Exports[0].Clients[0].Access = "rw"
	baseBytes, nextBytes := policyBytes(t, base), policyBytes(t, next)
	got, err := ReplaceFileServices(base, next)
	want := editConfig(2)
	want.FileServices = next
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("file-service edit did not preserve the complete iSCSI policy")
	}
	got.ISCSI.Backings[0].RelativePath = "luns/changed.img"
	got.ISCSI.Targets[0].LUNs[0].Access = "rw"
	got.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "other-ref"
	got.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "rw"
	got.FileServices.Shares.Volumes[0].ID = "other"
	got.FileServices.Shares.Users[0].Name = "other"
	got.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
	got.FileServices.NFS.Exports[0].Clients[0].Network = "192.0.2.10/32"
	if !bytes.Equal(baseBytes, policyBytes(t, base)) || !bytes.Equal(nextBytes, policyBytes(t, next)) {
		t.Fatal("returned configuration aliases caller-owned nested policy")
	}
}

func TestReplaceISCSIRetainsFileServicesAndIndependentValues(t *testing.T) {
	base := editConfig(1)
	next := editConfig(2).ISCSI
	next.Backings[0].CapacityBytes = 8192
	next.Targets[0].LUNs[0].Access = "rw"
	next.Targets[0].Initiators[0].Grants[0].Access = "rw"
	baseBytes, nextBytes := policyBytes(t, base), policyBytes(t, next)
	got, err := ReplaceISCSI(base, next)
	want := editConfig(2)
	want.ISCSI = next
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("iSCSI edit did not preserve the complete SMB/NFS policy")
	}
	got.FileServices.Shares.Volumes[0].ID = "other"
	got.FileServices.Shares.Users[0].Name = "other"
	got.FileServices.Shares.Shares[0].Grants[0].Access = "rw"
	got.FileServices.NFS.Exports[0].Clients[0].Network = "192.0.2.10/32"
	got.ISCSI.Backings[0].CapacityBytes = 16384
	got.ISCSI.Targets[0].LUNs[0].Access = "ro"
	got.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "other-ref"
	got.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "ro"
	if !bytes.Equal(baseBytes, policyBytes(t, base)) || !bytes.Equal(nextBytes, policyBytes(t, next)) {
		t.Fatal("returned configuration aliases caller-owned nested policy")
	}
}

func TestReplaceViewsRefuseInvalidOrStaleWithoutPartialState(t *testing.T) {
	for _, direction := range []string{"files", "iscsi"} {
		t.Run(direction, func(t *testing.T) {
			cases := []struct {
				name   string
				change func(*Config, *Config)
			}{
				{"missing base", func(base, _ *Config) { *base = Config{} }},
				{"invalid base", func(base, _ *Config) { base.ISCSI.Targets[0].Name = "" }},
				{"mixed base", func(base, _ *Config) { base.FileServices.NFS.VolumeRevision++ }},
				{"stale", func(_, next *Config) { *next = editConfig(1) }},
				{"skipped", func(_, next *Config) { *next = editConfig(3) }},
				{"overflow", func(base, next *Config) { *base = editConfig(^uint64(0)); *next = editConfig(1) }},
			}
			if direction == "files" {
				cases = append(cases, []struct {
					name   string
					change func(*Config, *Config)
				}{
					{"mixed next", func(_, next *Config) { next.FileServices.NFS.Revision++ }},
					{"retained NFS source rebound", func(_, next *Config) { next.FileServices.NFS.Exports[0].RelativePath = "changed" }},
					{"missing next collection", func(_, next *Config) { next.FileServices.NFS.Exports = nil }},
					{"iSCSI referenced volume rebound", func(_, next *Config) {
						next.FileServices.Shares.Volumes[0].FilesystemUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
					}},
					{"iSCSI referenced volume removed", func(_, next *Config) {
						next.FileServices.Shares.Volumes = []shareconfig.Volume{}
						next.FileServices.Shares.Shares = []shareconfig.Share{}
						next.FileServices.NFS.Exports = []nfsconfig.Export{}
						if next.FileServices.Validate() != nil {
							t.Fatal("file-only fixture must be valid")
						}
					}},
				}...)
			} else {
				cases = append(cases, []struct {
					name   string
					change func(*Config, *Config)
				}{
					{"mixed next", func(_, next *Config) { next.ISCSI.VolumeRevision = 1 }},
					{"missing next collection", func(_, next *Config) { next.ISCSI.Targets = nil }},
					{"unknown backing volume", func(_, next *Config) { next.ISCSI.Backings[0].VolumeID = "unknown" }},
				}...)
			}
			for _, spec := range cases {
				t.Run(spec.name, func(t *testing.T) {
					base, next := editConfig(1), editConfig(2)
					spec.change(&base, &next)
					beforeBase, beforeNext := policyBytes(t, base), policyBytes(t, next)
					var got Config
					var err error
					if direction == "files" {
						got, err = ReplaceFileServices(base, next.FileServices)
					} else {
						got, err = ReplaceISCSI(base, next.ISCSI)
					}
					if err != ErrInvalid || !reflect.DeepEqual(got, Config{}) {
						t.Fatal("edit returned partial or non-redacted failure")
					}
					if !bytes.Equal(beforeBase, policyBytes(t, base)) || !bytes.Equal(beforeNext, policyBytes(t, next)) {
						t.Fatal("refused edit modified its inputs")
					}
				})
			}
		})
	}
}

func TestReplaceViewsPreserveExactUint64Revision(t *testing.T) {
	base, next := editConfig(^uint64(0)-1), editConfig(^uint64(0))
	for _, replace := range []func() (Config, error){
		func() (Config, error) { return ReplaceFileServices(base, next.FileServices) },
		func() (Config, error) { return ReplaceISCSI(base, next.ISCSI) },
	} {
		got, err := replace()
		if err != nil || !reflect.DeepEqual(got, next) {
			t.Fatal("maximum valid revision lost precision")
		}
	}
}

func TestReplaceDenseViewsAllocationBudget(t *testing.T) {
	base, next := denseEditConfig(1), denseEditConfig(2)
	for _, files := range []bool{false, true} {
		var got Config
		var err error
		allocations := testing.AllocsPerRun(1, func() {
			if files {
				got, err = ReplaceFileServices(base, next.FileServices)
			} else {
				got, err = ReplaceISCSI(base, next.ISCSI)
			}
		})
		if err != nil || got.Revision != 2 {
			t.Fatal("dense edit failed")
		}
		if allocations > 50000 {
			t.Errorf("dense view files=%v exceeds allocation budget: %.0f", files, allocations)
		}
	}
}

func TestReplaceViewsPreserveExplicitEmptyCollections(t *testing.T) {
	base, next := testConfig(), testConfig()
	base.ISCSI.Backings, base.ISCSI.Targets = []iscsipolicy.Backing{}, []iscsipolicy.Target{}
	next.ISCSI.Backings, next.ISCSI.Targets = []iscsipolicy.Backing{}, []iscsipolicy.Target{}
	next.Revision, next.FileServices.Revision, next.FileServices.Shares.Revision = 2, 2, 2
	next.FileServices.NFS.Revision, next.FileServices.NFS.VolumeRevision = 2, 2
	next.ISCSI.Revision, next.ISCSI.VolumeRevision = 2, 2
	for _, replace := range []func() (Config, error){
		func() (Config, error) { return ReplaceFileServices(base, next.FileServices) },
		func() (Config, error) { return ReplaceISCSI(base, next.ISCSI) },
	} {
		got, err := replace()
		if err != nil || !reflect.DeepEqual(got, next) {
			t.Fatal("empty collection became null or invalid")
		}
		data := policyBytes(t, got)
		if _, err := Decode(bytes.NewReader(data)); err != nil {
			t.Fatal("edited empty configuration cannot be decoded")
		}
	}
}

func TestReplaceViewsConcurrentIndependentResults(t *testing.T) {
	base, next := editConfig(1), editConfig(2)
	baseBytes, nextBytes := policyBytes(t, base), policyBytes(t, next)
	var workers sync.WaitGroup
	failures := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(files bool) {
			defer workers.Done()
			var got Config
			var err error
			if files {
				got, err = ReplaceFileServices(base, next.FileServices)
			} else {
				got, err = ReplaceISCSI(base, next.ISCSI)
			}
			if err != nil {
				failures <- true
				return
			}
			got.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "rw"
			got.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
		}(i%2 == 0)
	}
	workers.Wait()
	if len(failures) != 0 || !bytes.Equal(baseBytes, policyBytes(t, base)) || !bytes.Equal(nextBytes, policyBytes(t, next)) {
		t.Fatal("concurrent edit results shared mutable input state")
	}
}

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

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsconfig

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func volumes() shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 3,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

func fixture() Policy {
	return Policy{Format: Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 3,
		Exports: []Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "Books & Comics",
			Clients: []Client{{Network: "192.0.2.10/32", Access: "rw", Squash: "all", AnonymousUID: 101000, AnonymousGID: 101000, Security: "sys"},
				{Network: "2001:db8::/64", Access: "ro", Squash: "root", AnonymousUID: 65534, AnonymousGID: 65534, Security: "krb5p"}}}}}
}

func TestPreviewClientMappingAndMountGuard(t *testing.T) {
	p := fixture()
	before, _ := json.Marshal(p)
	preview, err := Build(p, volumes())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/srv/phantowd/volumes/11111111-2222-3333-4444-555555555555/Books\\040&\\040Comics",
		"192.0.2.10/32(rw,sync,secure,root_squash,all_squash,subtree_check,nocrossmnt,sec=sys,anonuid=101000,anongid=101000,fsid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,mountpoint=/srv/phantowd/volumes/11111111-2222-3333-4444-555555555555)",
		"2001:db8::/64(ro,sync,secure,root_squash,subtree_check,nocrossmnt,sec=krb5p,anonuid=65534,anongid=65534",
	} {
		if !strings.Contains(preview.Table, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, forbidden := range []string{"no_root_squash", "async", "insecure", "*", "2001:db8::/64 ("} {
		if strings.Contains(preview.Table, forbidden) {
			t.Fatalf("unsafe output %q", forbidden)
		}
	}
	if !preview.UsesAUTH_SYS || !preview.RequiresKerberos || preview.VolumeRevision != 3 || preview.Exports[0].FilesystemUUID != volumes().Volumes[0].FilesystemUUID {
		t.Fatal("lost prerequisites")
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated caller policy")
	}
	p.Exports[0].Clients[0].Access = "ro"
	if preview.Exports[0].Clients[0].Access != "rw" {
		t.Fatal("preview aliases caller state")
	}
}

func TestDecodeRoundTripAndStrictFields(t *testing.T) {
	data, _ := json.Marshal(fixture())
	p, err := Decode(bytes.NewReader(data), volumes())
	if err != nil || !reflect.DeepEqual(p, fixture()) {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"duplicate":         bytes.Replace(data, []byte(`"revision":1`), []byte(`"revision":1,"revision":2`), 1),
		"escaped duplicate": bytes.Replace(data, []byte(`"revision":1`), []byte(`"revision":1,"revi\u0073ion":2`), 1),
		"unknown":           bytes.Replace(data, []byte(`"access"`), []byte(`"other"`), 1),
		"case alias":        bytes.Replace(data, []byte(`"access"`), []byte(`"Access"`), 1),
		"missing":           bytes.Replace(data, []byte(`"anonymous_uid":101000,`), nil, 1),
		"null":              bytes.Replace(data, []byte(`"anonymous_uid":101000`), []byte(`"anonymous_uid":null`), 1),
		"negative":          bytes.Replace(data, []byte(`"anonymous_uid":101000`), []byte(`"anonymous_uid":-1`), 1),
		"overflow":          bytes.Replace(data, []byte(`"anonymous_uid":101000`), []byte(`"anonymous_uid":4294967296`), 1),
		"trailing":          append(append([]byte{}, data...), data...),
		"oversize":          bytes.Repeat([]byte(" "), MaxInputBytes+1),
		"invalid UTF8":      append(append([]byte{}, data...), 255),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(bytes.NewReader(bad), volumes()); err == nil {
				t.Fatal("accepted unsafe JSON")
			}
		})
	}
}

func TestRejectInvalidPolicy(t *testing.T) {
	for name, change := range map[string]func(*Policy){
		"schema":             func(p *Policy) { p.SchemaVersion = 2 },
		"revision":           func(p *Policy) { p.Revision = 0 },
		"stale volume":       func(p *Policy) { p.VolumeRevision = 2 },
		"missing exports":    func(p *Policy) { p.Exports = nil },
		"missing volume":     func(p *Policy) { p.Exports[0].VolumeID = "missing" },
		"root fsid":          func(p *Policy) { p.Exports[0].ID = "0" },
		"zero fsid":          func(p *Policy) { p.Exports[0].ID = "00000000-0000-0000-0000-000000000000" },
		"duplicate export":   func(p *Policy) { p.Exports = append(p.Exports, p.Exports[0]) },
		"no clients":         func(p *Policy) { p.Exports[0].Clients = nil },
		"root anonymous uid": func(p *Policy) { p.Exports[0].Clients[0].AnonymousUID = 0 },
		"root anonymous gid": func(p *Policy) { p.Exports[0].Clients[0].AnonymousGID = 0 },
		"sentinel uid":       func(p *Policy) { p.Exports[0].Clients[0].AnonymousUID = math.MaxUint32 },
		"sentinel gid":       func(p *Policy) { p.Exports[0].Clients[0].AnonymousGID = math.MaxUint32 },
		"no squash":          func(p *Policy) { p.Exports[0].Clients[0].Squash = "none" },
		"missing security":   func(p *Policy) { p.Exports[0].Clients[0].Security = "" },
		"option injection":   func(p *Policy) { p.Exports[0].Clients[0].Access = "rw,no_root_squash" },
		"absolute path":      func(p *Policy) { p.Exports[0].RelativePath = "/etc" },
		"traversal":          func(p *Policy) { p.Exports[0].RelativePath = "../etc" },
		"newline":            func(p *Policy) { p.Exports[0].RelativePath = "books\n/ *(rw)" },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			change(&p)
			if _, err := Build(p, volumes()); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestRejectAmbiguousOrUnsafeNetworks(t *testing.T) {
	for _, network := range []string{"*", "client.example", "192.0.2.10", "192.0.2.10/24", "192.0.2.0/255.255.255.0", "0.0.0.0/0", "::/0",
		"0.0.0.0/32", "::/128", "224.0.0.0/4", "255.255.255.255/32", "128.0.0.0/1", "ff02::1/128", "::ffff:192.0.2.1/128", "fe80::1%eth0/128", "[2001:db8::]/64", "2001:DB8::/64", "192.0.2.10/032"} {
		p := fixture()
		p.Exports[0].Clients[0].Network = network
		if _, err := Build(p, volumes()); err == nil {
			t.Errorf("accepted network %q", network)
		}
	}
	p := fixture()
	duplicate := p.Exports[0].Clients[0]
	duplicate.Network = "192.0.2.0/24"
	p.Exports[0].Clients = append(p.Exports[0].Clients, duplicate)
	if _, err := Build(p, volumes()); err == nil {
		t.Fatal("accepted overlapping rules")
	}
}

func TestPathEscapingRootAndOverlap(t *testing.T) {
	p := fixture()
	p.Exports[0].RelativePath = `Books #1 "draft"`
	preview, err := Build(p, volumes())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Table, `Books\040\0431\040\042draft\042`) {
		t.Fatal("path not escaped", preview.Table)
	}
	p.Exports[0].RelativePath = "."
	preview, err = Build(p, volumes())
	if err != nil || !strings.Contains(preview.Table, ",no_subtree_check,") {
		t.Fatal("root policy", err)
	}
	second := p.Exports[0]
	second.ID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	second.RelativePath = "child"
	p.Exports = append(p.Exports, second)
	if _, err := Build(p, volumes()); err == nil {
		t.Fatal("accepted parent/child exports")
	}
}

func TestDeterminismAndEmptyPolicy(t *testing.T) {
	p := fixture()
	first, _ := Build(p, volumes())
	p.Exports[0].Clients[0], p.Exports[0].Clients[1] = p.Exports[0].Clients[1], p.Exports[0].Clients[0]
	second, err := Build(p, volumes())
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("unstable preview", err)
	}
	p.Exports = []Export{}
	preview, err := Build(p, volumes())
	if err != nil || len(preview.Exports) != 0 || preview.UsesAUTH_SYS || preview.RequiresKerberos {
		t.Fatal("empty policy", err)
	}
}

func FuzzPolicy(f *testing.F) {
	data, _ := json.Marshal(fixture())
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(bytes.NewReader(data), volumes())
		if err != nil {
			return
		}
		preview, err := Build(p, volumes())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(preview.Table, "\n") != len(p.Exports)+1 || strings.Contains(preview.Table, "no_root_squash") {
			t.Fatal("unsafe table")
		}
		again, err := Build(p, volumes())
		if err != nil || !reflect.DeepEqual(preview, again) {
			t.Fatal("unstable table")
		}
	})
}

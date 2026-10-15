// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func fixture() (shareconfig.Config, nfsconfig.Policy) {
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 2,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{{ID: "writer", Name: "alice"}},
		Shares:  []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "writer", Access: "rw"}}}}}
	nfs := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 2,
		Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "192.0.2.1/32", Access: "rw", Squash: "all", AnonymousUID: 101000, AnonymousGID: 101000, Security: "sys"}}}}}
	return shares, nfs
}

func encode(shares shareconfig.Config, nfs nfsconfig.Policy) []byte {
	data, _ := json.Marshal(map[string]any{"shares": shares, "nfs": nfs})
	return data
}

func TestCombinedPreviewIsNotActivation(t *testing.T) {
	shares, nfs := fixture()
	p, err := Decode(encode(shares, nfs))
	if err != nil {
		t.Fatal(err)
	}
	if p.Scope != "desired-policy-only" || p.SchemaVersion != 1 || p.Applied || p.Persisted || p.RuntimeValidated || p.ActivationAvailable {
		t.Fatal("preview crossed activation boundary")
	}
	if len(p.Samba.Shares) != 1 || len(p.NFS.Exports) != 1 || p.NFS.VolumeRevision != p.Samba.Revision {
		t.Fatal("incoherent service previews")
	}
	if !slices.Contains(p.Requirements, "auth_sys_network_trust") || !slices.Contains(p.Requirements, "cross_protocol_access_review") {
		t.Fatal("missing prerequisites")
	}
	nfs.Exports[0].Clients[0].Security = "krb5p"
	p, err = Decode(encode(shares, nfs))
	if err != nil || !slices.Contains(p.Requirements, "kerberos_provisioning") || slices.Contains(p.Requirements, "auth_sys_network_trust") {
		t.Fatal("incorrect transport prerequisites", err)
	}
}

func TestCombinedPreviewReportsSameVolumeCrossProtocolPathOverlap(t *testing.T) {
	shares, nfs := fixture()
	p, err := Decode(encode(shares, nfs))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Requirements, "cross_protocol_path_overlap") {
		t.Fatal("same-volume SMB/NFS path overlap was not called out for review")
	}
}

func TestCombinedPreviewPathOverlapIsVolumeScopedAndSegmentAware(t *testing.T) {
	cases := []struct {
		name      string
		sharePath string
		nfsPath   string
		sameVol   bool
		want      bool
	}{
		{name: "SMB parent", sharePath: "media", nfsPath: "media/books", sameVol: true, want: true},
		{name: "NFS parent", sharePath: "media/books", nfsPath: "media", sameVol: true, want: true},
		{name: "root", sharePath: ".", nfsPath: "media", sameVol: true, want: true},
		{name: "segment prefix is not overlap", sharePath: "media", nfsPath: "media-old", sameVol: true},
		{name: "different logical volume", sharePath: "media", nfsPath: "media", sameVol: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			shares, nfs := fixture()
			shares.Shares[0].RelativePath = test.sharePath
			nfs.Exports[0].RelativePath = test.nfsPath
			if !test.sameVol {
				shares.Volumes = append(shares.Volumes, shareconfig.Volume{ID: "archive", FilesystemUUID: "22222222-3333-4444-5555-666666666666"})
				nfs.Exports[0].VolumeID = "archive"
			}
			preview, err := Decode(encode(shares, nfs))
			if err != nil {
				t.Fatal(err)
			}
			got := slices.Contains(preview.Requirements, "cross_protocol_path_overlap")
			if got != test.want {
				t.Fatalf("overlap requirement = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRejectEnvelopeAndPolicyAmbiguities(t *testing.T) {
	shares, nfs := fixture()
	data := encode(shares, nfs)
	for name, input := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"), "missing": []byte(`{"shares":{}}`),
		"unknown":           bytes.Replace(data, []byte(`"shares":`), []byte(`"other":`), 1),
		"case":              bytes.Replace(data, []byte(`"shares":`), []byte(`"Shares":`), 1),
		"duplicate":         bytes.Replace(data, []byte(`"nfs":`), []byte(`"nfs":{},"nfs":`), 1),
		"escaped duplicate": bytes.Replace(data, []byte(`"nfs":`), []byte(`"nfs":{},"nf\u0073":`), 1),
		"null member":       bytes.Replace(data, []byte(`"nfs":`), []byte(`"nfs":null,"nfs":`), 1),
		"trailing":          append(append([]byte{}, data...), []byte("{}")...),
		"oversized":         bytes.Repeat([]byte(" "), MaxInputBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(input); !errors.Is(err, ErrEnvelope) {
				t.Fatal("envelope accepted", err)
			}
		})
	}
	shares.Revision = 0
	if _, err := Decode(encode(shares, nfs)); !errors.Is(err, ErrShares) {
		t.Fatal(err)
	}
	shares, nfs = fixture()
	nfs.VolumeRevision = 99
	if _, err := Decode(encode(shares, nfs)); !errors.Is(err, ErrNFS) {
		t.Fatal(err)
	}
	shares, nfs = fixture()
	shares.Shares[0].RelativePath = "books%U"
	if _, err := Decode(encode(shares, nfs)); !errors.Is(err, ErrSamba) {
		t.Fatal(err)
	}
	// Nested duplicate fields and malformed Unicode are still rejected by the
	// service decoders rather than normalized by an envelope struct decode.
	for _, invalid := range [][]byte{
		bytes.Replace(data, []byte(`"volume_revision":2`), []byte(`"volume_revision":2,"volume_revision":2`), 1),
		bytes.Replace(data, []byte(`"relative_path":"books"`), []byte(`"relative_path":"\ud800"`), 1),
	} {
		if _, err := Decode(invalid); err == nil {
			t.Fatal("invalid nested policy accepted")
		}
	}
}

// Actual producer output, not hand-written browser JSON. These dense cases
// exercise valid large policies and encoding/json's HTML escaping. They are
// regression samples, not a proof of the maximum of all possible policies.
func TestRenderedPoliciesFitBrowserResponseBudgets(t *testing.T) {
	for _, pathText := range []string{strings.Repeat("x", 512), strings.Repeat("&", 384)} {
		c := configFixture(1)
		c.Shares.Users = nil
		for i := 0; i < 128; i++ {
			c.Shares.Users = append(c.Shares.Users, shareconfig.User{ID: fmt.Sprintf("u%03d", i), Name: fmt.Sprintf("u%03d%s", i, strings.Repeat("x", 28))})
		}
		baseShare, baseExport := c.Shares.Shares[0], c.NFS.Exports[0]
		c.Shares.Shares, c.NFS.Exports = nil, nil
		for i := 0; i < 32; i++ {
			s := baseShare
			s.ID, s.Name, s.RelativePath = fmt.Sprintf("s%03d", i), fmt.Sprintf("S%03d%s", i, strings.Repeat("x", 76)), fmt.Sprintf("s%03d/%s", i, pathText)
			s.Grants = nil
			for _, user := range c.Shares.Users {
				s.Grants = append(s.Grants, shareconfig.Grant{UserID: user.ID, Access: "rw"})
			}
			c.Shares.Shares = append(c.Shares.Shares, s)
		}
		for i := 0; i < 16; i++ {
			e := baseExport
			e.ID, e.RelativePath = fmt.Sprintf("%08x-2222-3333-4444-555555555555", i+1), fmt.Sprintf("e%03d/%s", i, pathText)
			e.Clients = nil
			for j := 0; j < 64; j++ {
				client := baseExport.Clients[0]
				client.Network, client.Security = fmt.Sprintf("2001:db8:%x::/48", j+1), "krb5p"
				client.AnonymousUID, client.AnonymousGID = 4294967294, 4294967294
				e.Clients = append(e.Clients, client)
			}
			c.NFS.Exports = append(c.NFS.Exports, e)
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Shares.Validate(); err != nil {
			t.Fatal("dense share fixture", err)
		}
		if err := c.NFS.Validate(c.Shares); err != nil {
			t.Fatal("dense NFS fixture", err)
		}
		validated, err := DecodeConfig(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal("dense producer fixture is not valid", err)
		}
		preview, err := Build(validated.Shares, validated.NFS)
		if err != nil {
			t.Fatal(err)
		}
		for _, sample := range []struct {
			name  string
			value any
			limit int
		}{
			{"configuration", map[string]any{"configuration": validated}, 525056},
			{"preview", preview, 4 << 20},
			{"restore", map[string]any{"configuration": validated, "preview": preview}, 4 << 20},
		} {
			data, err := json.Marshal(sample.value)
			if err != nil || len(data)+256 > sample.limit {
				t.Fatalf("%s producer exceeds browser response budget: bytes=%d error=%v", sample.name, len(data), err)
			}
			t.Logf("%s bytes=%d, plus256-byte envelope reserve, cap=%d", sample.name, len(data), sample.limit)
		}
	}
}

func FuzzPreviewEnvelope(f *testing.F) {
	shares, nfs := fixture()
	f.Add(encode(shares, nfs))
	f.Add([]byte(`{"shares":{},"nfs":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			return
		}
		if p.Applied || p.Persisted || p.RuntimeValidated || p.ActivationAvailable {
			t.Fatal("unsafe preview")
		}
		again, err := Decode(data)
		if err != nil || !reflect.DeepEqual(p, again) {
			t.Fatal("unstable preview")
		}
	})
}

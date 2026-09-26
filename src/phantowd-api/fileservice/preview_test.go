// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
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

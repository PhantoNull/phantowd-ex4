// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

const testInstallation = "11111111222233334444555555555555"
const testPolicy = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[],"targets":[]}}`

func policyAt(t *testing.T, revision uint64) []byte {
	t.Helper()
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = revision, revision, revision
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = revision, revision
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = revision, revision
	wire, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestDocumentStrictRecordsAndExactOpening(t *testing.T) {
	base, next := policyAt(t, 1), policyAt(t, 2)
	o, err := policyevidence.DeclareEpochOpening(testInstallation, "aaaaaaaabbbbccccddddeeeeeeeeeeee", 1, base)
	if err != nil {
		t.Fatal(err)
	}
	opening, err := policyevidence.EncodeEpochOpening(o)
	if err != nil {
		t.Fatal(err)
	}
	opening = append(opening, '\n')
	d := openingDocument(testInstallation, opening)
	for _, close := range []bool{false, true} {
		if close {
			c, err := policyevidence.DeclareEpochClosure(opening, next)
			if err != nil {
				t.Fatal(err)
			}
			closing, err := policyevidence.EncodeEpochClosure(c)
			if err != nil {
				t.Fatal(err)
			}
			d.Revision = 2
			d.Closure = base64.StdEncoding.EncodeToString(closing)
		}
		wire, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		back, err := decodeDocument(bytes.NewReader(wire))
		if err != nil || back != d {
			t.Fatal("record roundtrip")
		}
		decoded, err := recordBytes(back.Opening, false)
		if err != nil || !bytes.Equal(decoded, opening) {
			t.Fatal("opening reformatted")
		}
		for _, bad := range [][]byte{
			[]byte(`{}`), append(bytes.Clone(wire), []byte(`{}`)...), bytes.Repeat([]byte(" "), maxDocumentBytes+1),
			[]byte(strings.Replace(string(wire), `"schema_version":1`, `"schema_version":2`, 1)),
			[]byte(strings.Replace(string(wire), `"format":`, `"extra":null,"format":`, 1)),
			[]byte(strings.Replace(string(wire), `"revision":`, `"revision":1,"revision":`, 1)),
		} {
			if got, err := decodeDocument(bytes.NewReader(bad)); err != ErrInvalid || got != (document{}) {
				t.Fatal("invalid document accepted")
			}
		}
		padded := append(bytes.Clone(wire), bytes.Repeat([]byte(" "), maxDocumentBytes-len(wire))...)
		if _, err := decodeDocument(bytes.NewReader(padded)); err != nil {
			t.Fatal("inclusive bound refused")
		}
		if _, err := decodeDocument(bytes.NewReader(append(padded, ' '))); err != ErrInvalid {
			t.Fatal("excess bytes accepted")
		}
	}
	bad := d
	bad.Closure = ""
	if bad.validate() != ErrInvalid {
		t.Fatal("missing closure accepted")
	}
	bad = d
	bad.Revision = 1
	if bad.validate() != ErrInvalid {
		t.Fatal("closure in opening accepted")
	}
	bad = d
	bad.Opening = base64.StdEncoding.EncodeToString(bytes.TrimSpace(opening))
	if bad.validate() != ErrInvalid {
		t.Fatal("opening byte substitution accepted")
	}
	bad = d
	bad.Opening = "\n" + bad.Opening
	if bad.validate() != ErrInvalid {
		t.Fatal("noncanonical base64 accepted")
	}
	if _, err := decodeDocument(nil); err != ErrInvalid {
		t.Fatal("nil reader")
	}
}

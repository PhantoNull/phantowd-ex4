// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

const testInstallation = "11111111222233334444555555555555"

// Invented policy: no backing, credential or share path is ever opened.
const testPolicy = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[{"id":"bulk","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],"users":[{"id":"writer","name":"alice"}],"shares":[{"id":"books","name":"Books","volume_id":"bulk","relative_path":"books","grants":[{"user_id":"writer","access":"rw"}]}]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","volume_id":"bulk","relative_path":"books","clients":[{"network":"127.0.0.1/32","access":"ro","squash":"all","anonymous_uid":101000,"anonymous_gid":101000,"security":"sys"}]}]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[{"id":"backing","volume_id":"bulk","relative_path":"luns/not-opened.img","capacity_bytes":4096,"block_size":512,"allocation":"sparse"}],"targets":[{"id":"target","name":"iqn.2001-04.com.example:target","state":"disabled","luns":[{"id":"lun","number":0,"backing_id":"backing","access":"ro"}],"initiators":[{"name":"iqn.2001-04.com.example:peer","authentication":{"mode":"chap","initiator_user":"invented-user","initiator_secret_ref":"invented-reference"},"grants":[{"lun_id":"lun","access":"ro"}]}]}]}}`

func revision(c *naspolicy.Config, n uint64) {
	c.Revision = n
	c.FileServices.Revision = n
	c.FileServices.Shares.Revision = n
	c.FileServices.NFS.Revision = n
	c.FileServices.NFS.VolumeRevision = n
	c.ISCSI.Revision = n
	c.ISCSI.VolumeRevision = n
}
func fixture(t testing.TB) (bundle, []byte, naspolicy.Config) {
	t.Helper()
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	base, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	base = append(base, '\n', ' ')
	revision(&c, 2)
	p, err := policyevidence.Prepare(testInstallation, base, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := intentBundle(testInstallation, p)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := p.CandidateBytes()
	return b, candidate, c
}
func TestBundlePreservesExactBaseAndBindsLocalDeclaration(t *testing.T) {
	b, candidate, _ := fixture(t)
	for _, confirmed := range []bool{false, true} {
		if confirmed {
			var e error
			b, e = confirmedBundle(b)
			if e != nil {
				t.Fatal(e)
			}
		}
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeBundle(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(got, b) {
			t.Fatal("private exact roundtrip", err)
		}
		if !bytes.HasSuffix(got.base, []byte("\n ")) {
			t.Fatal("base compacted")
		}
		rc := policyevidence.Slot{State: policyevidence.Absent}
		want := policyevidence.PublicationUnconfirmed
		if confirmed {
			rc = policyevidence.Slot{State: policyevidence.Present, Data: got.receipt}
			want = policyevidence.LocalConfirmationObserved
		}
		d, err := policyevidence.Match(policyevidence.Evidence{InstallationID: testInstallation, Current: policyevidence.Slot{State: policyevidence.Present, Data: candidate}, Intent: policyevidence.Slot{State: policyevidence.Present, Data: got.intent}, Receipt: rc})
		if err != nil || d.Kind() != want {
			t.Fatal("declaration binding", err)
		}
		got.base[0] = '!'
		if b.base[0] != '{' {
			t.Fatal("decoded bytes alias original")
		}
		if strings.Contains(fmt.Sprintf("%+v", b), testInstallation) {
			t.Fatal("format disclosed private tuple")
		}
	}
}
func TestBundleStrictEnvelopeCanonicalBase64AndBindings(t *testing.T) {
	b, _, _ := fixture(t)
	valid, _ := json.Marshal(b)
	var w bundleWire
	if json.Unmarshal(valid, &w) != nil {
		t.Fatal("wire")
	}
	for _, change := range []func(*bundleWire){
		func(w *bundleWire) { w.Format = "unknown" }, func(w *bundleWire) { w.SchemaVersion = 2 }, func(w *bundleWire) { w.Revision = 0 }, func(w *bundleWire) { w.Revision = 3 },
		func(w *bundleWire) { w.Phase = "local-confirmed" }, func(w *bundleWire) { w.Receipt = w.Intent }, func(w *bundleWire) { w.Installation = strings.Repeat("a", 32) },
		func(w *bundleWire) { w.Base = "" }, func(w *bundleWire) { w.Intent = "" }, func(w *bundleWire) { w.Base += "\n" }, func(w *bundleWire) { w.Intent = "!!!!" },
		func(w *bundleWire) { w.Base = base64.StdEncoding.EncodeToString(bytes.TrimSpace(b.base)) },
		func(w *bundleWire) {
			w.Base = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), naspolicy.MaxInputBytes+1))
		},
	} {
		bad := w
		change(&bad)
		data, _ := json.Marshal(bad)
		if v, err := decodeBundle(bytes.NewReader(data)); err != ErrInvalid || !reflect.DeepEqual(v, bundle{}) {
			t.Fatal("invalid bundle escaped")
		}
	}
	for _, data := range [][]byte{nil, []byte("null"), []byte("{}"), append(bytes.Clone(valid), 'x'),
		[]byte(strings.Replace(string(valid), `"format":`, `"Format":`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":null`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"revision":1`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"unknown":true`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1.0`, 1)),
	} {
		if v, err := decodeBundle(bytes.NewReader(data)); err != ErrInvalid || !reflect.DeepEqual(v, bundle{}) {
			t.Fatal("envelope refusal", string(data[:min(len(data), 24)]))
		}
	}
	other, _, _ := fixture(t)
	confirmed, _ := confirmedBundle(other)
	bad := b
	bad.revision = 2
	bad.receipt = confirmed.receipt
	if bad.validate() != ErrInvalid {
		t.Fatal("foreign operation receipt accepted")
	}
	if _, err := canonicalBytes("Zh==", 4, false); err != ErrInvalid {
		t.Fatal("nonzero base64 padding bits")
	}
	if _, err := decodeBundle(nil); err != ErrInvalid {
		t.Fatal("nil reader")
	}
	if _, err := decodeBundle(failedReader{}); err != ErrInvalid {
		t.Fatal("read error leaked")
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE") }

var _ io.Reader = failedReader{}

func TestBundleFullBoundsAndZeroInvalid(t *testing.T) {
	b, _, c := fixture(t)
	base := append(bytes.Clone(b.base), bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(b.base))...)
	p, err := policyevidence.Prepare(testInstallation, base, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err = intentBundle(testInstallation, p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, bytes.Repeat([]byte(" "), maxBundleBytes-len(data))...)
	if got, err := decodeBundle(bytes.NewReader(data)); err != nil || !bytes.Equal(got.base, base) {
		t.Fatal("inclusive bundle/base bounds", err)
	}
	if got, err := decodeBundle(bytes.NewReader(append(data, ' '))); err != ErrInvalid || !reflect.DeepEqual(got, bundle{}) {
		t.Fatal("excess bound")
	}
	if _, err := json.Marshal(bundle{}); err == nil {
		t.Fatal("zero bundle serialized")
	}
	if _, err := intentBundle(testInstallation, policyevidence.Prepared{}); err != ErrInvalid {
		t.Fatal("zero preparation")
	}
	if _, err := confirmedBundle(bundle{}); err != ErrInvalid {
		t.Fatal("zero confirmation")
	}
}
func FuzzBundleDecoder(f *testing.F) {
	b, _, _ := fixture(f)
	data, _ := json.Marshal(b)
	f.Add(data)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		b, err := decodeBundle(bytes.NewReader(data))
		if err != nil {
			if !reflect.DeepEqual(b, bundle{}) {
				t.Fatal("partial bundle")
			}
			return
		}
		wire, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBundle(bytes.NewReader(wire)); err != nil {
			t.Fatal("valid roundtrip", err)
		}
	})
}

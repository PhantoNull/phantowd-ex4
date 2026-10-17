// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const installation = "11111111222233334444555555555555"
const operation = "aaaaaaaabbbbccccddddeeeeeeeeeeee"
const policyFixture = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,
"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,
"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[{"id":"bulk","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],"users":[{"id":"writer","name":"alice"}],"shares":[{"id":"books","name":"Books","volume_id":"bulk","relative_path":"books","grants":[{"user_id":"writer","access":"rw"}]}]},
"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","volume_id":"bulk","relative_path":"books","clients":[{"network":"127.0.0.1/32","access":"ro","squash":"all","anonymous_uid":101000,"anonymous_gid":101000,"security":"sys"}]}]}},
"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[{"id":"backing","volume_id":"bulk","relative_path":"luns/not-opened.img","capacity_bytes":4096,"block_size":512,"allocation":"sparse"}],"targets":[{"id":"target","name":"iqn.2001-04.com.example:target","state":"disabled","luns":[{"id":"lun","number":0,"backing_id":"backing","access":"ro"}],"initiators":[{"name":"iqn.2001-04.com.example:peer","authentication":{"mode":"chap","initiator_user":"private-user","initiator_secret_ref":"private-ref"},"grants":[{"lun_id":"lun","access":"ro"}]}]}]}}`

func policy(t testing.TB, revision uint64) []byte {
	t.Helper()
	c, err := naspolicy.Decode(strings.NewReader(policyFixture))
	if err != nil {
		t.Fatal("invalid complete fixture", err)
	}
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = revision, revision, revision
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = revision, revision
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = revision, revision
	if revision%2 == 0 {
		c.ISCSI.Targets[0].State = "enabled"
	}
	data, err := json.Marshal(c)
	if err != nil || c.Validate() != nil {
		t.Fatal("invalid coherent revision")
	}
	return data
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func fixture(t testing.TB) (Evidence, Intent, Receipt) {
	t.Helper()
	base, next := policy(t, 7), policy(t, 8)
	i := Intent{tuple{installation, operation, 7, 8, digest(base), digest(next)}}
	r := Receipt{value: i.value}
	ib, err := EncodeIntent(i)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := EncodeReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{InstallationID: installation, Intent: Slot{Present, ib}, Receipt: Slot{Present, rb}, Current: Slot{Present, next}}, i, r
}

func TestMatchCompletePolicyAndAllEvidenceStates(t *testing.T) {
	e, _, _ := fixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Evidence)
		want   Kind
	}{
		{"local", func(*Evidence) {}, LocalConfirmationObserved},
		{"no records", func(e *Evidence) { e.Intent = Slot{State: Absent}; e.Receipt = Slot{State: Absent} }, NoRecordedOperation},
		{"base only", func(e *Evidence) { e.Receipt = Slot{State: Absent}; e.Current.Data = policy(t, 7) }, IntentBaseObserved},
		{"published no receipt", func(e *Evidence) { e.Receipt = Slot{State: Absent} }, PublicationUnconfirmed},
		{"receipt with base", func(e *Evidence) { e.Current.Data = policy(t, 7) }, InconsistentEvidence},
		{"orphan receipt", func(e *Evidence) { e.Intent = Slot{State: Absent} }, InconsistentEvidence},
		{"foreign installation", func(e *Evidence) { e.InstallationID = operation }, InconsistentEvidence},
		{"unrelated valid policy", func(e *Evidence) { e.Current.Data = policy(t, 9) }, InconsistentEvidence},
		{"same revision different exact bytes", func(e *Evidence) { e.Current.Data = append(append([]byte{}, e.Current.Data...), '\n') }, InconsistentEvidence},
		{"missing policy", func(e *Evidence) { e.Current = Slot{State: Absent} }, IncompleteEvidence},
		{"unavailable current", func(e *Evidence) { e.Current = Slot{} }, IncompleteEvidence},
		{"unavailable intent", func(e *Evidence) { e.Intent = Slot{} }, IncompleteEvidence},
		{"unavailable receipt", func(e *Evidence) { e.Receipt = Slot{} }, IncompleteEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := e
			tc.change(&input)
			got, err := Match(input)
			if err != nil || got.Kind() != tc.want {
				t.Fatalf("wrong redacted kind %v %v", got, err)
			}
		})
	}
	before := append([]byte{}, e.Current.Data...)
	for n := 0; n < 20; n++ {
		if d, err := Match(e); err != nil || d.Kind() != LocalConfirmationObserved {
			t.Fatal(d, err)
		}
	}
	if !bytes.Equal(before, e.Current.Data) {
		t.Fatal("matcher mutated source")
	}
}

func TestMatchChecksEveryTupleBindingAndCurrentSchema(t *testing.T) {
	e, i, r := fixture(t)
	for _, change := range []func(*tuple){
		func(t *tuple) { t.InstallationID = operation }, func(t *tuple) { t.OperationID = installation },
		func(t *tuple) { t.BaseRevision = 8; t.NextRevision = 9 },
		func(t *tuple) { t.BaseSHA256 = strings.Repeat("0", 64) }, func(t *tuple) { t.NextSHA256 = strings.Repeat("0", 64) },
	} {
		bad := r
		change(&bad.value)
		data, err := EncodeReceipt(bad)
		if err != nil {
			t.Fatal(err)
		}
		input := e
		input.Receipt.Data = data
		if d, err := Match(input); err != nil || d.Kind() != InconsistentEvidence {
			t.Fatal("tuple mismatch admitted", d, err)
		}
	}
	// Both digest and schema-validated revision must match, never either alone.
	i.value.BaseSHA256, i.value.NextSHA256 = i.value.NextSHA256, i.value.BaseSHA256
	e.Intent.Data, _ = EncodeIntent(i)
	e.Receipt = Slot{State: Absent}
	for _, rev := range []uint64{7, 8} {
		e.Current.Data = policy(t, rev)
		if d, err := Match(e); err != nil || d.Kind() != InconsistentEvidence {
			t.Fatal("revision/hash binding lost", d, err)
		}
	}
	e, _, _ = fixture(t)
	for _, change := range []func(*Evidence){
		func(e *Evidence) { e.InstallationID = "" },
		func(e *Evidence) { e.Intent.State = 99 },
		func(e *Evidence) { e.Intent.Data = nil },
		func(e *Evidence) { e.Receipt = Slot{Absent, []byte("PRIVATE")} },
		func(e *Evidence) { e.Current = Slot{Unavailable, []byte("PRIVATE")} },
		func(e *Evidence) { e.Current.Data = []byte("PRIVATE") },
		func(e *Evidence) { e.Intent.Data = []byte("PRIVATE") },
		func(e *Evidence) { e.Receipt.Data = []byte("PRIVATE") },
		func(e *Evidence) {
			e.Current.Data = bytes.Replace(e.Current.Data, []byte(`"volume_revision":8`), []byte(`"volume_revision":9`), 1)
		},
		func(e *Evidence) { e.Current.Data = append(e.Current.Data, []byte(`{}`)...) },
		func(e *Evidence) { e.Current.Data = bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes+1) },
	} {
		input := e
		change(&input)
		if d, err := Match(input); err != ErrInvalid || d != (Diagnosis{}) {
			t.Fatal("invalid evidence returned partial data", d, err)
		}
	}
	// Missing roles give no partial positive match, even when other bytes exist.
	e.Current = Slot{}
	e.Intent.Data = []byte("PRIVATE")
	if d, err := Match(e); err != nil || d.Kind() != IncompleteEvidence {
		t.Fatal("incomplete census evaluated partial evidence")
	}
}

type privateFailure struct{}

func (privateFailure) Read([]byte) (int, error) { return 0, errors.New("PRIVATE READ FAILURE") }
func TestRecordCodecsStrictBoundedAndPrivate(t *testing.T) {
	e, i, r := fixture(t)
	for _, receipt := range []bool{false, true} {
		data := e.Intent.Data
		if receipt {
			data = e.Receipt.Data
		}
		check := func(reader io.Reader) error {
			if receipt {
				got, err := DecodeReceipt(reader)
				if err != nil && got != (Receipt{}) {
					t.Fatal("partial receipt")
				}
				return err
			}
			got, err := DecodeIntent(reader)
			if err != nil && got != (Intent{}) {
				t.Fatal("partial intent")
			}
			return err
		}
		for _, malformed := range []string{
			`null`, `{}`, string(data) + `{}`, string(data) + ` PRIVATE`,
			strings.Replace(string(data), `"schema_version":1`, `"schema_version":2`, 1),
			strings.Replace(string(data), `"schema_version":1`, `"schema_version":1.0`, 1),
			strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
			strings.Replace(string(data), `"operation_id":`, `"Operation_id":`, 1),
			strings.Replace(string(data), `"operation_id":"`+operation+`"`, `"operation_id":null`, 1),
			strings.Replace(string(data), operation, strings.ToUpper(operation), 1),
			strings.Replace(string(data), operation, strings.Repeat("0", 32), 1),
			strings.Replace(string(data), operation, `\ud800`, 1),
			strings.Replace(string(data), operation, "\xff", 1),
			strings.Replace(string(data), `"base_revision":7`, `"base_revision":0`, 1),
			strings.Replace(string(data), `"next_revision":8`, `"next_revision":9`, 1),
			strings.Replace(string(data), `"base_revision":7`, `"base_revision":18446744073709551615`, 1),
			strings.Replace(string(data), `"next_revision":8`, `"next_revision":18446744073709551616`, 1),
			strings.Replace(string(data), `"next_revision":8`, `"next_revision":8e0`, 1),
			strings.Replace(string(data), `"base_sha256":"`+i.value.BaseSHA256+`"`, `"base_sha256":"not-a-digest"`, 1),
			strings.Replace(string(data), `"format":`, `"unknown":true,"format":`, 1),
			strings.Repeat(" ", MaxRecordBytes+1),
		} {
			if err := check(strings.NewReader(malformed)); err != ErrInvalid {
				t.Fatal("malformed record admitted", receipt)
			}
		}
		if err := check(nil); err != ErrInvalid {
			t.Fatal("nil reader")
		}
		if err := check(privateFailure{}); err != ErrInvalid {
			t.Fatal("read failure was not fixed")
		}
		padded := append(append([]byte{}, data...), bytes.Repeat([]byte(" "), MaxRecordBytes-len(data))...)
		if err := check(bytes.NewReader(padded)); err != nil {
			t.Fatal("inclusive record bound rejected")
		}
		if err := check(bytes.NewReader(append(padded, ' '))); err != ErrInvalid {
			t.Fatal("record overflow admitted")
		}
	}
	for _, input := range []string{strings.Replace(string(e.Receipt.Data), `"phase":"local-confirmed"`, `"phase":"confirmed"`, 1), string(e.Intent.Data)} {
		if _, err := DecodeReceipt(strings.NewReader(input)); err != ErrInvalid {
			t.Fatal("receipt phase/format lost")
		}
	}
	if _, err := DecodeIntent(bytes.NewReader(e.Receipt.Data)); err != ErrInvalid {
		t.Fatal("receipt accepted as intent")
	}
	for _, t := range []tuple{{}, {installation, operation, math.MaxUint64, 0, i.value.BaseSHA256, i.value.NextSHA256}} {
		if b, err := EncodeIntent(Intent{t}); err != ErrInvalid || b != nil {
			panic("invalid encode")
		}
		if b, err := EncodeReceipt(Receipt{t}); err != ErrInvalid || b != nil {
			panic("invalid encode")
		}
	}
	decoded, err := DecodeIntent(bytes.NewReader(e.Intent.Data))
	if err != nil || decoded != i {
		t.Fatal("intent roundtrip")
	}
	decodedR, err := DecodeReceipt(bytes.NewReader(e.Receipt.Data))
	if err != nil || decodedR != r {
		t.Fatal("receipt roundtrip")
	}
}

func TestPrivateFormattingAndGenericJSONRefusal(t *testing.T) {
	e, i, r := fixture(t)
	d, err := Match(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{i, &i, r, &r, e, &e, e.Current, &e.Current, d, &d} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%20.2v"} {
			out := fmt.Sprintf(format, value)
			for _, private := range []string{installation, operation, i.value.BaseSHA256, i.value.NextSHA256, "private-user", "private-ref", "filesystem_uuid", "not-opened.img"} {
				if strings.Contains(out, private) {
					t.Fatal("private field escaped formatting")
				}
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivate) {
			t.Fatal("generic serialization admitted")
		}
	}
	for _, value := range []any{&i, &r, &e, &e.Current, &d} {
		if err := json.Unmarshal([]byte(`{}`), value); !errors.Is(err, ErrPrivate) {
			t.Fatal("generic decoding admitted")
		}
	}
}

func TestMaximumRevisionAndInclusivePolicyBytes(t *testing.T) {
	e, _, _ := fixture(t)
	base, next := policy(t, math.MaxUint64-1), policy(t, math.MaxUint64)
	next = append(next, bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(next))...)
	v := tuple{installation, operation, math.MaxUint64 - 1, math.MaxUint64, digest(base), digest(next)}
	var err error
	e.Intent.Data, err = EncodeIntent(Intent{v})
	if err != nil {
		t.Fatal(err)
	}
	e.Receipt.Data, err = EncodeReceipt(Receipt{v})
	if err != nil {
		t.Fatal(err)
	}
	e.Current.Data = next
	if d, err := Match(e); err != nil || d.Kind() != LocalConfirmationObserved {
		t.Fatal("exact maximum values lost", d, err)
	}
	e.Receipt = Slot{State: Absent}
	e.Current.Data = base
	if d, err := Match(e); err != nil || d.Kind() != IntentBaseObserved {
		t.Fatal("maximum base lost", d, err)
	}
}

func FuzzRecordCodecs(f *testing.F) {
	e, _, _ := fixture(f)
	f.Add(e.Intent.Data)
	f.Add(e.Receipt.Data)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		i, err := DecodeIntent(bytes.NewReader(data))
		if err != nil {
			if err != ErrInvalid || i != (Intent{}) {
				t.Fatal("partial intent")
			}
		} else {
			b, err := EncodeIntent(i)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeIntent(bytes.NewReader(b))
			if err != nil || again != i {
				t.Fatal("intent roundtrip")
			}
		}
		r, err := DecodeReceipt(bytes.NewReader(data))
		if err != nil {
			if err != ErrInvalid || r != (Receipt{}) {
				t.Fatal("partial receipt")
			}
		} else {
			b, err := EncodeReceipt(r)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeReceipt(bytes.NewReader(b))
			if err != nil || again != r {
				t.Fatal("receipt roundtrip")
			}
		}
	})
}

func FuzzMatchEvidence(f *testing.F) {
	e, _, _ := fixture(f)
	f.Add(e.Intent.Data, e.Receipt.Data, e.Current.Data)
	f.Fuzz(func(t *testing.T, intent, receipt, current []byte) {
		if len(intent) > MaxRecordBytes+1 || len(receipt) > MaxRecordBytes+1 || len(current) > 8192 {
			t.Skip()
		}
		input := Evidence{installation, Slot{Present, intent}, Slot{Present, receipt}, Slot{Present, current}}
		d, err := Match(input)
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(d, Diagnosis{}) {
				t.Fatal("partial diagnosis")
			}
			return
		}
		if d.Kind() != LocalConfirmationObserved && d.Kind() != InconsistentEvidence {
			t.Fatal("unexpected complete-record state")
		}
	})
}

func TestIntentMatchesOnlyItsValidatedOperationID(t *testing.T) {
	_, intent, _ := fixture(t)
	for _, id := range []string{operation, strings.Repeat("b", 32), strings.ToUpper(operation), "", strings.Repeat("0", 32), operation + "extra"} {
		if got := intent.MatchesOperationID(id); got != (id == operation) {
			t.Fatal("operation binding predicate")
		}
		if (Intent{}).MatchesOperationID(id) {
			t.Fatal("zero intent matched an operation")
		}
	}
}

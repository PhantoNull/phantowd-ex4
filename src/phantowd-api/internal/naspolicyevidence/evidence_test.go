// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyevidence_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	e "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const installation = "11111111111111111111111111111111"

func policy(t testing.TB, revision uint64) []byte {
	t.Helper()
	access := "ro"
	if revision > 1 {
		access = "rw"
	}
	c := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: revision,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
				Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Backings: []iscsipolicy.Backing{{ID: "disk", VolumeID: "bulk", RelativePath: "luns/disk.img", CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}},
			Targets: []iscsipolicy.Target{{ID: "target", Name: "iqn.2001-04.com.example:target", State: "disabled",
				LUNs: []iscsipolicy.LUN{{ID: "lun", Number: 0, BackingID: "disk", Access: access}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:peer",
					Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "peer", InitiatorSecretRef: "inbound"},
					Grants:         []iscsipolicy.Grant{{LUNID: "lun", Access: access}}}}}}}}
	if c.Validate() != nil {
		t.Fatal("invalid synthetic policy")
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtures(t testing.TB) (base, next, intent, receipt []byte) {
	t.Helper()
	base, next = policy(t, 1), policy(t, 2)
	r := map[string]any{"format": e.IntentFormat, "schema_version": 1, "installation_id": installation,
		"operation_id": "22222222222222222222222222222222", "base_revision": 1, "next_revision": 2,
		"base_sha256": fmt.Sprintf("%x", sha256.Sum256(base)), "next_sha256": fmt.Sprintf("%x", sha256.Sum256(next))}
	intent, _ = json.Marshal(r)
	r["format"], r["phase"] = e.ReceiptFormat, "local-confirmed"
	receipt, _ = json.Marshal(r)
	return
}

func TestMatchingLocalRecordsPreservesInputs(t *testing.T) {
	_, current, intent, receipt := fixtures(t)
	originals := [][]byte{bytes.Clone(current), bytes.Clone(intent), bytes.Clone(receipt)}
	if e.Inspect(installation, current, intent, receipt, true) != e.MatchingLocalRecords {
		t.Fatal("matching local records not observed")
	}
	for i, data := range [][]byte{current, intent, receipt} {
		if !bytes.Equal(data, originals[i]) {
			t.Fatal("observation changed caller input")
		}
	}
}

func TestUncertaintyClassifications(t *testing.T) {
	base, next, intent, receipt := fixtures(t)
	for _, tc := range []struct {
		name                     string
		current, intent, receipt []byte
		complete                 bool
		want                     e.Kind
	}{
		{"no-records", base, nil, nil, true, e.NoRecordedOperation},
		{"base-only", base, intent, nil, true, e.UnconfirmedBase},
		{"published-without-receipt", next, intent, nil, true, e.UnconfirmedPublication},
		{"matching", next, intent, receipt, true, e.MatchingLocalRecords},
		{"orphan-receipt", next, nil, receipt, true, e.Inconsistent},
		{"receipt-with-old-policy", base, intent, receipt, true, e.Inconsistent},
		{"unrelated-current", policy(t, 3), intent, receipt, true, e.Inconsistent},
		{"incomplete", next, intent, receipt, false, e.Unavailable},
		{"missing-current", nil, intent, receipt, true, e.Unavailable},
		{"invalid-current", []byte("{truncated"), intent, receipt, true, e.InvalidPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.Inspect(installation, tc.current, tc.intent, tc.receipt, tc.complete); got != tc.want {
				t.Fatalf("classification %d, want %d", got, tc.want)
			}
		})
	}
}

func TestStrictRecordsAndExactCurrentBinding(t *testing.T) {
	_, current, intent, receipt := fixtures(t)
	check := func(bad []byte, isReceipt bool) {
		t.Helper()
		i, r := bad, receipt
		if isReceipt {
			i, r = intent, bad
		}
		if e.Inspect(installation, current, i, r, true) != e.Inconsistent {
			t.Fatal("invalid record accepted")
		}
	}
	for _, isReceipt := range []bool{false, true} {
		good := intent
		if isReceipt {
			good = receipt
		}
		for _, field := range []struct {
			key   string
			value any
		}{
			{"format", "foreign"}, {"schema_version", 2}, {"installation_id", strings.Repeat("0", 32)},
			{"installation_id", strings.Repeat("aB", 16)}, {"installation_id", strings.Repeat("3", 32)},
			{"operation_id", strings.Repeat("0", 32)}, {"operation_id", "short"}, {"operation_id", strings.Repeat("4", 32)},
			{"base_revision", 0}, {"base_revision", uint64(math.MaxUint64)}, {"base_revision", 1.5},
			{"next_revision", 3}, {"base_sha256", "short"}, {"base_sha256", strings.Repeat("A", 64)},
			{"next_sha256", strings.Repeat("0", 64)}, {"phase", "client-acknowledged"}, {"unknown", "private"},
		} {
			var fields map[string]any
			if json.Unmarshal(good, &fields) != nil {
				t.Fatal("fixture")
			}
			fields[field.key] = field.value
			bad, _ := json.Marshal(fields)
			check(bad, isReceipt)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(good, &fields)
		for key := range fields {
			var missing map[string]json.RawMessage
			_ = json.Unmarshal(good, &missing)
			delete(missing, key)
			bad, _ := json.Marshal(missing)
			check(bad, isReceipt)
		}
		for _, bad := range [][]byte{[]byte{}, []byte("null"), []byte("{}"), append(bytes.Clone(good), '{', '}'),
			bytes.Replace(good, []byte(`"operation_id":`), []byte(`"operation_id":null,"duplicate":`), 1),
			bytes.Replace(good, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
			bytes.Replace(good, []byte(`"format"`), []byte(`"Format"`), 1), append([]byte{0xff}, good...),
			bytes.Replace(good, []byte(`"operation_id":"22222222222222222222222222222222"`), []byte(`"operation_id":"\ud800"`), 1),
			bytes.Replace(good, []byte(`"operation_id":"22222222222222222222222222222222"`), []byte(`"operation_id":{"operation_id":{"operation_id":"deep"}}`), 1),
			append(bytes.Clone(good), bytes.Repeat([]byte(" "), e.MaxRecordBytes-len(good)+1)...)} {
			check(bad, isReceipt)
		}
	}
	if e.Inspect(installation, append(bytes.Clone(current), ' '), intent, receipt, true) != e.Inconsistent {
		t.Fatal("semantic policy equality replaced exact byte binding")
	}
	pad := func(data []byte) []byte {
		return append(bytes.Clone(data), bytes.Repeat([]byte(" "), e.MaxRecordBytes-len(data))...)
	}
	if e.Inspect(installation, current, pad(intent), pad(receipt), true) != e.MatchingLocalRecords {
		t.Fatal("inclusive byte bound refused")
	}
	if e.Inspect(strings.Repeat("0", 32), current, intent, receipt, true) != e.Unavailable {
		t.Fatal("missing trusted installation accepted")
	}
}

func FuzzInspect(f *testing.F) {
	_, current, intent, receipt := fixtures(f)
	f.Add(current, intent, receipt)
	f.Fuzz(func(t *testing.T, current, intent, receipt []byte) {
		before := [3][32]byte{sha256.Sum256(current), sha256.Sum256(intent), sha256.Sum256(receipt)}
		got := e.Inspect(installation, current, intent, receipt, true)
		if got > e.Inconsistent || got != e.Inspect(installation, current, intent, receipt, true) ||
			e.Inspect(installation, current, intent, receipt, false) != e.Unavailable || before != [3][32]byte{sha256.Sum256(current), sha256.Sum256(intent), sha256.Sum256(receipt)} {
			t.Fatal("observation lost determinism, completeness or input ownership")
		}
	})
}

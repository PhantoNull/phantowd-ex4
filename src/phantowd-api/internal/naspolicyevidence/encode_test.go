// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyevidence_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	e "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

func TestEncodeOperationMatchesExactBeforeAndAfterWithoutMutation(t *testing.T) {
	base, next := policy(t, 1), policy(t, 2)
	before, after := bytes.Clone(base), bytes.Clone(next)
	intent, receipt, err := e.EncodeOperation(installation, "22222222222222222222222222222222", base, next)
	if err != nil || len(intent) == 0 || len(receipt) == 0 || len(intent) > e.MaxRecordBytes || len(receipt) > e.MaxRecordBytes {
		t.Fatal("bounded operation records unavailable", err)
	}
	if e.Inspect(installation, base, intent, nil, true) != e.UnconfirmedBase ||
		e.Inspect(installation, next, intent, nil, true) != e.UnconfirmedPublication ||
		e.Inspect(installation, next, intent, receipt, true) != e.MatchingLocalRecords {
		t.Fatal("encoded tuple does not match exact policies")
	}
	if !bytes.Equal(before, base) || !bytes.Equal(after, next) {
		t.Fatal("encoding mutated policy bytes")
	}
}

func TestEncodeOperationRetainsNFSSourceBindings(t *testing.T) {
	for _, change := range []string{"unchanged", "access", "path", "volume", "filesystem"} {
		t.Run(change, func(t *testing.T) {
			var base, next naspolicy.Config
			if json.Unmarshal(policy(t, 1), &base) != nil || json.Unmarshal(policy(t, 2), &next) != nil {
				t.Fatal("fixture decode")
			}
			for _, c := range []*naspolicy.Config{&base, &next} {
				c.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "media",
					Clients: []nfsconfig.Client{{Network: "192.0.2.8/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
			}
			switch change {
			case "access":
				next.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
			case "path":
				next.FileServices.NFS.Exports[0].RelativePath = "other"
			case "volume":
				next.FileServices.Shares.Volumes[0].ID, next.FileServices.NFS.Exports[0].VolumeID, next.ISCSI.Backings[0].VolumeID = "other", "other", "other"
			case "filesystem":
				next.FileServices.Shares.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
			}
			if base.Validate() != nil || next.Validate() != nil {
				t.Fatal("binding fixture is not independently valid")
			}
			b, _ := json.Marshal(base)
			n, _ := json.Marshal(next)
			intent, receipt, err := e.EncodeOperation(installation, "22222222222222222222222222222222", b, n)
			if change == "unchanged" || change == "access" {
				if err != nil || e.Inspect(installation, n, intent, receipt, true) != e.MatchingLocalRecords {
					t.Fatal("safe desired edit refused", err)
				}
			} else if err == nil || intent != nil || receipt != nil {
				t.Fatal("retained source rebind produced records")
			}
		})
	}
}

func TestEncodeOperationRefusesInvalidPairsWithoutPartialRecords(t *testing.T) {
	base, next := policy(t, 1), policy(t, 2)
	for _, tc := range []struct {
		name, installation, operation string
		base, next                    []byte
	}{
		{"zero-installation", strings.Repeat("0", 32), strings.Repeat("2", 32), base, next},
		{"uppercase-installation", strings.Repeat("AB", 16), strings.Repeat("2", 32), base, next},
		{"zero-operation", installation, strings.Repeat("0", 32), base, next},
		{"short-operation", installation, "short", base, next},
		{"oversized-operation", installation, strings.Repeat("2", 8192), base, next},
		{"missing-base", installation, strings.Repeat("2", 32), nil, next},
		{"missing-next", installation, strings.Repeat("2", 32), base, nil},
		{"truncated-base", installation, strings.Repeat("2", 32), []byte(`{"private-detail":"do-not-echo"`), next},
		{"trailing-document", installation, strings.Repeat("2", 32), base, append(bytes.Clone(next), '{', '}')},
		{"invalid-utf8", installation, strings.Repeat("2", 32), append(bytes.Clone(base), 0xff), next},
		{"future-schema", installation, strings.Repeat("2", 32), base, bytes.Replace(next, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)},
		{"mixed-revision", installation, strings.Repeat("2", 32), base, bytes.Replace(next, []byte(`"revision":2`), []byte(`"revision":1`), 1)},
		{"same-revision", installation, strings.Repeat("2", 32), base, base},
		{"skipped-revision", installation, strings.Repeat("2", 32), base, policy(t, 3)},
		{"overflow", installation, strings.Repeat("2", 32), policy(t, math.MaxUint64), policy(t, 1)},
		{"oversized-base", installation, strings.Repeat("2", 32), append(bytes.Clone(base), bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(base)+1)...), next},
		{"oversized-next", installation, strings.Repeat("2", 32), base, append(bytes.Clone(next), bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(next)+1)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := sha256.Sum256(tc.base), sha256.Sum256(tc.next)
			intent, receipt, err := e.EncodeOperation(tc.installation, tc.operation, tc.base, tc.next)
			if err == nil || intent != nil || receipt != nil {
				t.Fatal("invalid pair produced partial or usable records")
			}
			if strings.Contains(err.Error(), "do-not-echo") {
				t.Fatal("input detail exposed")
			}
			if sha256.Sum256(tc.base) != before || sha256.Sum256(tc.next) != after {
				t.Fatal("refusal mutated inputs")
			}
		})
	}
}

func TestEncodeOperationBindsRawBytesAndOperationWithExactLargeRevisions(t *testing.T) {
	for _, revision := range []uint64{1 << 53, math.MaxUint64 - 1} {
		base := append([]byte("\n\t"), policy(t, revision)...)
		next := append(policy(t, revision+1), ' ', '\n')
		intent, receipt, err := e.EncodeOperation(installation, strings.Repeat("2", 32), base, next)
		if err != nil || e.Inspect(installation, base, intent, nil, true) != e.UnconfirmedBase || e.Inspect(installation, next, intent, receipt, true) != e.MatchingLocalRecords {
			t.Fatal("raw bytes or uint64 precision lost", err)
		}
		if e.Inspect(installation, bytes.TrimSpace(next), intent, receipt, true) != e.Inconsistent {
			t.Fatal("canonicalized policy replaced exact byte binding")
		}
		i2, r2, err := e.EncodeOperation(installation, strings.Repeat("3", 32), base, next)
		if err != nil || e.Inspect(installation, next, i2, r2, true) != e.MatchingLocalRecords || e.Inspect(installation, next, intent, r2, true) != e.Inconsistent {
			t.Fatal("operation tuples mixed", err)
		}
		i3, r3, err := e.EncodeOperation(installation, strings.Repeat("2", 32), base, next)
		if err != nil || !bytes.Equal(intent, i3) || !bytes.Equal(receipt, r3) {
			t.Fatal("pure encoding is nondeterministic", err)
		}
		for _, forbidden := range []string{"iqn.", "luns/disk.img", "inbound", "file_services"} {
			if bytes.Contains(intent, []byte(forbidden)) || bytes.Contains(receipt, []byte(forbidden)) {
				t.Fatal("raw policy detail entered metadata records")
			}
		}
	}
}

func TestEncodeOperationAcceptsInclusivePolicyBounds(t *testing.T) {
	base, next := policy(t, 1), policy(t, 2)
	base = append(base, bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(base))...)
	next = append(next, bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(next))...)
	intent, receipt, err := e.EncodeOperation(installation, strings.Repeat("2", 32), base, next)
	if err != nil || len(intent) > e.MaxRecordBytes || len(receipt) > e.MaxRecordBytes || e.Inspect(installation, next, intent, receipt, true) != e.MatchingLocalRecords {
		t.Fatal("inclusive policy limit refused or unbounded metadata produced", err)
	}
}

func FuzzEncodeOperation(f *testing.F) {
	f.Add(policy(f, 1), policy(f, 2))
	f.Add([]byte("null"), []byte("{}"))
	f.Fuzz(func(t *testing.T, base, next []byte) {
		before, after := sha256.Sum256(base), sha256.Sum256(next)
		intent, receipt, err := e.EncodeOperation(installation, strings.Repeat("2", 32), base, next)
		if (err != nil && (intent != nil || receipt != nil)) || (err == nil && e.Inspect(installation, next, intent, receipt, true) != e.MatchingLocalRecords) {
			t.Fatal("encoding lost all-or-error or exact tuple binding")
		}
		if sha256.Sum256(base) != before || sha256.Sum256(next) != after {
			t.Fatal("encoding mutated input")
		}
	})
}

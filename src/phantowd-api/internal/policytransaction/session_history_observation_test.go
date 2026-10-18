// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestNamedSessionHistoryBindsExpectedOriginAndAllInputs(t *testing.T) {
	anchor, current, ops, _ := bundleHistoryFixture(t)
	o, _ := policyevidence.DeclareEpochOpening(testInstallation, strings.Repeat("a", 32), 1, anchor.Data)
	opening, _ := policyevidence.EncodeEpochOpening(o)
	c, _ := policyevidence.DeclareEpochClosure(opening, current.Data)
	closing, _ := policyevidence.EncodeEpochClosure(c)
	wire, err := json.Marshal(map[string]any{"format": "phantowd-policy-session-journal-experimental", "schema_version": 1, "revision": 2, "installation_id": testInstallation, "opening": base64.StdEncoding.EncodeToString(opening), "closure": base64.StdEncoding.EncodeToString(closing)})
	if err != nil {
		t.Fatal(err)
	}
	journal := policyevidence.Slot{State: policyevidence.Present, Data: wire}
	entries := []NamedBundleObservation{{bundleHistoryName(t, ops[1].Data), ops[1]}, {bundleHistoryName(t, ops[0].Data), ops[0]}}
	if d, err := MatchNamedSessionHistoryObservation(testInstallation, journal, anchor, current, entries); err != nil || d.Kind() != policyevidence.ClosureSessionHistoryObserved {
		t.Fatal("joined named observation", d, err)
	}
	if d, err := MatchNamedSessionHistoryObservation(strings.Repeat("b", 32), journal, anchor, current, entries); err != nil || d.Kind() != policyevidence.InconsistentSessionEvidence {
		t.Fatal("foreign expected identity accepted")
	}
	before := bytes.Clone(entries[0].Operation.Data)
	for _, mode := range []string{"bad-name", "duplicate", "name-content", "malformed-later", "count", "aggregate", "journal"} {
		draft := append([]NamedBundleObservation(nil), entries...)
		j := journal
		switch mode {
		case "bad-name":
			draft[0].Name = "../not-a-record"
		case "duplicate":
			draft[0].Name = draft[1].Name
		case "name-content":
			draft[0].Name = strings.Repeat("f", 32) + ".json"
		case "malformed-later":
			j = policyevidence.Slot{State: policyevidence.Absent}
			draft[1].Operation = policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}
		case "count":
			for len(draft) <= policyevidence.MaxHistoryOperations {
				draft = append(draft, entries[0])
			}
		case "aggregate":
			draft[0].Operation.Data = bytes.Repeat([]byte{' '}, policyevidence.MaxHistoryInputBytes)
		case "journal":
			j.Data = []byte(`{}`)
		}
		if d, err := MatchNamedSessionHistoryObservation(testInstallation, j, anchor, current, draft); err != ErrInvalid || d.Kind() != "" {
			t.Fatal("invalid named session produced partial diagnosis", mode, d, err)
		}
	}
	if !bytes.Equal(before, entries[0].Operation.Data) {
		t.Fatal("caller data mutated")
	}
}

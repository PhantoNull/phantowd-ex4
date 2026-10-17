// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func bundleHistoryFixture(t testing.TB) (policyevidence.Slot, policyevidence.Slot, []policyevidence.Slot, []byte) {
	t.Helper()
	b, after, _ := fixture(t)
	defer b.clear()
	first, err := confirmedBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer first.clear()
	next, err := naspolicy.Decode(bytes.NewReader(after))
	if err != nil {
		t.Fatal(err)
	}
	revision(&next, 3)
	p, err := policyevidence.Prepare(testInstallation, after, next)
	if err != nil {
		t.Fatal(err)
	}
	secondIntent, err := intentBundle(testInstallation, p)
	if err != nil {
		t.Fatal(err)
	}
	defer secondIntent.clear()
	second, err := confirmedBundle(secondIntent)
	if err != nil {
		t.Fatal(err)
	}
	defer second.clear()
	one, _ := json.Marshal(first)
	two, _ := json.Marshal(second)
	unconfirmed, _ := json.Marshal(secondIntent)
	current, _ := p.CandidateBytes()
	present := func(data []byte) policyevidence.Slot {
		return policyevidence.Slot{State: policyevidence.Present, Data: data}
	}
	return present(bytes.Clone(b.base)), present(current), []policyevidence.Slot{present(one), present(two)}, unconfirmed
}

func TestBundleHistoryComposesRealCodecsAndExactChain(t *testing.T) {
	anchor, current, operations, _ := bundleHistoryFixture(t)
	operations[0], operations[1] = operations[1], operations[0]
	before := bytes.Clone(operations[0].Data)
	d, err := MatchBundleHistoryObservation(testInstallation, anchor, current, operations)
	if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
		t.Fatal("bundle history", d, err)
	}
	if !bytes.Equal(before, operations[0].Data) {
		t.Fatal("input wire mutated")
	}
}

func TestBundleHistoryRefusesIncompleteMalformedAndForeignEvidence(t *testing.T) {
	for _, name := range []string{"missing", "unavailable", "malformed", "wrong-profile", "bad-slot", "missing-data", "oversize", "count", "unconfirmed", "foreign"} {
		t.Run(name, func(t *testing.T) {
			anchor, current, ops, unconfirmed := bundleHistoryFixture(t)
			id := testInstallation
			want := policyevidence.IncompleteEvidence
			invalid := false
			switch name {
			case "missing":
				ops[1] = policyevidence.Slot{State: policyevidence.Absent}
			case "unavailable":
				ops[1] = policyevidence.Slot{}
			case "malformed":
				ops[1].Data = []byte(`{"format":"private malformed"}`)
				invalid = true
			case "wrong-profile":
				ops[1].Data = bytes.ReplaceAll(ops[1].Data, []byte(bundleFormat), []byte("phantowd-other-profile"))
				invalid = true
			case "bad-slot":
				ops[1].State = 255
				invalid = true
			case "missing-data":
				ops[1].Data = nil
				invalid = true
			case "oversize":
				ops[1].Data = bytes.Repeat([]byte{' '}, MaxObservedBundleBytes+1)
				invalid = true
			case "count":
				for len(ops) <= policyevidence.MaxHistoryOperations {
					ops = append(ops, ops[0])
				}
				invalid = true
			case "unconfirmed":
				ops[1].Data = unconfirmed
				want = policyevidence.PublicationUnconfirmed
			case "foreign":
				id = strings.Repeat("a", 32)
				want = policyevidence.InconsistentEvidence
			}
			d, err := MatchBundleHistoryObservation(id, anchor, current, ops)
			if invalid {
				if !errors.Is(err, ErrInvalid) || d != (policyevidence.Diagnosis{}) {
					t.Fatal("invalid history gave partial diagnosis", d, err)
				}
			} else if err != nil || d.Kind() != want {
				t.Fatal("bundle history refusal", d, err, want)
			}
		})
	}
}

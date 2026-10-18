// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestObservedDocumentHistoryExpectedIdentityAndStrictSlots(t *testing.T) {
	base := policyAt(t, 1)
	o, _ := policyevidence.DeclareEpochOpening(testInstallation, strings.Repeat("a", 32), 1, base)
	opening, _ := policyevidence.EncodeEpochOpening(o)
	doc := openingDocument(testInstallation, opening)
	anchor := policyevidence.Slot{State: policyevidence.Present, Data: base}
	for _, closed := range []bool{false, true} {
		want := policyevidence.OpenSessionHistoryObserved
		if closed {
			c, _ := policyevidence.DeclareEpochClosure(opening, base)
			closing, _ := policyevidence.EncodeEpochClosure(c)
			doc.Revision, doc.Closure = 2, base64.StdEncoding.EncodeToString(closing)
			want = policyevidence.ClosureSessionHistoryObserved
		}
		wire, _ := json.Marshal(doc)
		if d, err := MatchObservedHistory(testInstallation, policyevidence.Slot{State: policyevidence.Present, Data: wire}, anchor, anchor, nil); err != nil || d.Kind() != want {
			t.Fatal("strict document observation", d, err)
		}
		if d, err := MatchObservedHistory(strings.Repeat("b", 32), policyevidence.Slot{State: policyevidence.Present, Data: wire}, anchor, anchor, nil); err != nil || d.Kind() != policyevidence.InconsistentSessionEvidence {
			t.Fatal("foreign journal self-certified identity")
		}
		padded := append(bytes.Clone(wire), bytes.Repeat([]byte{' '}, MaxObservedDocumentBytes-len(wire))...)
		if d, err := MatchObservedHistory(testInstallation, policyevidence.Slot{State: policyevidence.Present, Data: padded}, anchor, anchor, nil); err != nil || d.Kind() != want {
			t.Fatal("inclusive journal bound refused")
		}
	}
	for _, slot := range []policyevidence.Slot{{State: policyevidence.Present}, {State: 255}, {State: policyevidence.Absent, Data: []byte("x")}, {State: policyevidence.Present, Data: []byte(`{}`)}, {State: policyevidence.Present, Data: bytes.Repeat([]byte{' '}, MaxObservedDocumentBytes+1)}} {
		if d, err := MatchObservedHistory(testInstallation, slot, anchor, anchor, nil); err != ErrInvalid || d.Kind() != "" {
			t.Fatal("invalid document returned diagnosis")
		}
	}
	for _, state := range []policyevidence.ObservationState{policyevidence.Absent, policyevidence.Unavailable} {
		slot := policyevidence.Slot{State: state}
		if d, err := MatchObservedHistory(testInstallation, slot, anchor, anchor, nil); err != nil || d.Kind() != policyevidence.IncompleteSessionEvidence {
			t.Fatal("missing journal treated as pristine")
		}
		ops := []policyevidence.HistoryOperation{{Intent: policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}}}
		if d, err := MatchObservedHistory(testInstallation, slot, anchor, anchor, ops); err != ErrInvalid || d.Kind() != "" {
			t.Fatal("missing journal hid malformed operation")
		}
	}
}

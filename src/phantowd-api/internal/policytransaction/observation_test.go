// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestBundleObservationSixKindsExactBytesAndNoInputMutation(t *testing.T) {
	b, candidate, _ := fixture(t)
	defer b.clear()
	confirmed, err := confirmedBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer confirmed.clear()
	intentWire, _ := json.Marshal(b)
	confirmedWire, _ := json.Marshal(confirmed)
	present := func(data []byte) policyevidence.Slot {
		return policyevidence.Slot{State: policyevidence.Present, Data: data}
	}
	for _, tc := range []struct {
		name               string
		current, operation policyevidence.Slot
		want               policyevidence.Kind
	}{
		{"no-operation", present(candidate), policyevidence.Slot{State: policyevidence.Absent}, policyevidence.NoRecordedOperation},
		{"base", present(b.base), present(intentWire), policyevidence.IntentBaseObserved},
		{"published", present(candidate), present(intentWire), policyevidence.PublicationUnconfirmed},
		{"confirmed", present(candidate), present(confirmedWire), policyevidence.LocalConfirmationObserved},
		{"receipt-with-base", present(b.base), present(confirmedWire), policyevidence.InconsistentEvidence},
		{"base-whitespace", present(bytes.TrimSpace(b.base)), present(intentWire), policyevidence.InconsistentEvidence},
		{"next-whitespace", present(append(bytes.Clone(candidate), ' ')), present(confirmedWire), policyevidence.InconsistentEvidence},
		{"missing-current", policyevidence.Slot{State: policyevidence.Absent}, present(confirmedWire), policyevidence.IncompleteEvidence},
		{"unavailable-current", policyevidence.Slot{}, present(intentWire), policyevidence.IncompleteEvidence},
		{"unavailable-operation", present(candidate), policyevidence.Slot{}, policyevidence.IncompleteEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current, operation := bytes.Clone(tc.current.Data), bytes.Clone(tc.operation.Data)
			for range 2 {
				d, err := MatchBundleObservation(testInstallation, tc.current, tc.operation)
				if err != nil || d.Kind() != tc.want {
					t.Fatal("incorrect redacted diagnosis", d, err)
				}
				if !bytes.Equal(current, tc.current.Data) || !bytes.Equal(operation, tc.operation.Data) {
					t.Fatal("caller bytes mutated")
				}
			}
		})
	}
	d, err := MatchBundleObservation(strings.Repeat("a", 32), present(candidate), present(confirmedWire))
	if err != nil || d.Kind() != policyevidence.InconsistentEvidence {
		t.Fatal("foreign installation was usable", d, err)
	}
}

func TestBundleObservationStrictSlotsBoundsAndZeroOnError(t *testing.T) {
	b, candidate, _ := fixture(t)
	defer b.clear()
	wire, _ := json.Marshal(b)
	current := policyevidence.Slot{State: policyevidence.Present, Data: candidate}
	operation := policyevidence.Slot{State: policyevidence.Present, Data: wire}
	bad := []policyevidence.Slot{
		{State: policyevidence.ObservationState(99)}, {State: policyevidence.Present},
		{State: policyevidence.Absent, Data: []byte("private")}, {Data: []byte("private")},
		{State: policyevidence.Present, Data: []byte("null")},
	}
	for _, s := range bad {
		for _, op := range []bool{false, true} {
			c, o := current, operation
			if op {
				o = s
			} else {
				c = s
			}
			if d, err := MatchBundleObservation(testInstallation, c, o); err != ErrInvalid || d.Kind() != "" {
				t.Fatal("invalid slot exposed diagnosis", d, err)
			}
		}
	}
	for _, data := range [][]byte{append(bytes.Clone(wire), 'x'), bytes.Repeat([]byte(" "), MaxObservedBundleBytes+1),
		[]byte(strings.Replace(string(wire), `"revision":1`, `"revision":1,"revision":1`, 1))} {
		for _, c := range []policyevidence.Slot{current, {State: policyevidence.Absent}} {
			if d, err := MatchBundleObservation(testInstallation, c, policyevidence.Slot{State: policyevidence.Present, Data: data}); err != ErrInvalid || d.Kind() != "" {
				t.Fatal("malformed present bundle hidden by missing current", d, err)
			}
		}
	}
	for _, id := range []string{"", strings.Repeat("0", 32), strings.Repeat("A", 32)} {
		if d, err := MatchBundleObservation(id, current, operation); err != ErrInvalid || d.Kind() != "" {
			t.Fatal("invalid expected installation", d, err)
		}
	}
	current.Data = append(bytes.Clone(candidate), bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(candidate))...)
	if d, err := MatchBundleObservation(testInstallation, current, policyevidence.Slot{State: policyevidence.Absent}); err != nil || d.Kind() != policyevidence.NoRecordedOperation {
		t.Fatal("inclusive policy bound", d, err)
	}
	current.Data = append(current.Data, ' ')
	if d, err := MatchBundleObservation(testInstallation, current, policyevidence.Slot{}); err != ErrInvalid || d.Kind() != "" {
		t.Fatal("oversize policy hidden by unavailable operation", d, err)
	}
}

func FuzzBundleObservation(f *testing.F) {
	b, candidate, _ := fixture(f)
	wire, _ := json.Marshal(b)
	b.clear()
	f.Add(candidate, wire)
	f.Add([]byte("null"), []byte("{}"))
	f.Fuzz(func(t *testing.T, current, operation []byte) {
		if len(current) > 8192 || len(operation) > 16384 {
			t.Skip()
		}
		c, o := bytes.Clone(current), bytes.Clone(operation)
		d, err := MatchBundleObservation(testInstallation, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.Slot{State: policyevidence.Present, Data: operation})
		if err != nil && (err != ErrInvalid || d.Kind() != "") {
			t.Fatal("partial/error disclosure")
		}
		if !bytes.Equal(c, current) || !bytes.Equal(o, operation) {
			t.Fatal("input mutation")
		}
	})
}
